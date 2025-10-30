from dataclasses import dataclass
from http import HTTPMethod, HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Any, Callable
import threading
import time
import json
import multiprocessing
from multiprocessing.connection import Connection


__all__ = ["AxonServer", "AxonServerOptions", "AxonServerFeedback"]


@dataclass
class AxonServerOptions:
    max_content_length: int = 1 * 1024 * 1024  # 1MiB
    """
    Maximum content length for POST requests.
    All requests with a Content-Length header value greater than max_content_length
    will receive a 413 Content Too Large response.
    """

    max_post_requests: int = 5
    """
    Maximum simultaneous POST requests.
    If the number of processing requests is equal to max_post_requests,
    other incoming requests will receive a 429 Too Many Requests response.
    """

    post_request_timeout: int = 5 * 60
    """
    Time in seconds after which the POST request handler will receive SIGTERM
    and the client will receive a 504 Gateway Timeout.
    """

    post_request_graceful_shutdown_timeout: int = 2 * 60
    """
    Time in seconds after which the POST request handler will receive SIGKILL
    if it has not finished after receiving SIGTERM.
    """


@dataclass
class AxonServerFeedback:
    set_request_timeout: Callable[[int], None]
    """
    Overrides `AxonServerOptions.post_request_timeout` for the current request,
    does not affect the timeout for processing other requests.
    """


@dataclass
class _HandlerFeedback:
    new_timeout: int | None = None


class AxonServer(ThreadingMixIn, HTTPServer):
    """
    A multi-threaded HTTP server with POST request limiting.
    """

    def __init__(
        self, listen_address: str, port: int, options=AxonServerOptions()
    ) -> None:
        super().__init__((listen_address, port), AxonHandler, bind_and_activate=False)

        self._methods: dict[HTTPMethod, dict[str, callable]] = {}
        self._options: AxonServerOptions = options

        self._post_requests_lock = threading.Lock()
        self._post_requests_running = 0

    def get(self, path: str, handle: callable):
        self.__route(HTTPMethod.GET, path, handle)

    def post(self, path: str, handle: callable):
        self.__route(HTTPMethod.POST, path, handle)

    def __route(self, method: HTTPMethod, path: str, handle: callable):
        methods = self._methods.setdefault(method, {})

        if path in methods:
            raise ValueError(f"handle for {method} {path} already exists")

        methods[path] = handle

    def _find_route(self, method: HTTPMethod, path: str):
        handlers = self._methods.get(method)
        return handlers.get(path)

    def run(self):
        """
        Binds to the port and runs the server.
        """
        try:
            self.server_bind()
            self.server_activate()
            self.serve_forever()
        except:
            self.server_close()
            raise


class AxonHandler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        """Add the response header to the headers buffer and log the
        response code.

        Unlike send_response from BaseHTTPRequestHandler
        does not set the Server header.
        """
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())

    def do_GET(self):
        server = self.__get_server()

        handler = server._find_route(HTTPMethod.GET, self.path)
        if handler is None:
            return self.__response(HTTPStatus.NOT_FOUND)

        try:
            result = handler()
            self.__response(result)
        except:
            self.__response(HTTPStatus.INTERNAL_SERVER_ERROR)
            raise

    def do_POST(self):
        server = self.__get_server()

        handler = server._find_route(HTTPMethod.POST, self.path)
        if handler is None:
            return self.__response(HTTPStatus.NOT_FOUND)

        # Check the number of simultaneous requests before reading and validating
        # request body to avoid unnecessary memory usage.
        with server._post_requests_lock:
            if server._post_requests_running < server._options.max_post_requests:
                server._post_requests_running += 1
            else:
                return self.__response(HTTPStatus.TOO_MANY_REQUESTS)

        try:
            body = self.__read_request_body(server._options)

            # Something went wrong, early return
            if isinstance(body, HTTPStatus):
                return self.__response(body)

            result = self.__run_handler(handler, body, server._options)
            self.__response(result)
        except BrokenPipeError:
            # Client closed the connection before we sent a response.
            pass
        except:
            self.__response(HTTPStatus.INTERNAL_SERVER_ERROR)
            raise
        finally:
            with server._post_requests_lock:
                server._post_requests_running -= 1

    def __read_request_body(self, options: AxonServerOptions) -> str | HTTPStatus:
        content_length = self.headers.get("Content-Length")
        if not isinstance(content_length, str) or not content_length.isdecimal():
            return HTTPStatus.LENGTH_REQUIRED

        content_length = int(content_length)
        if content_length >= options.max_content_length:
            return HTTPStatus.REQUEST_ENTITY_TOO_LARGE

        body = self.rfile.read(content_length)

        try:
            return body.decode()
        except UnicodeError:
            return HTTPStatus.BAD_REQUEST

    def __run_handler(self, handler: callable, body: str, options: AxonServerOptions):
        POLL_INTERVAL = 0.2

        def worker(pipe: Connection, handler: Callable[[str, AxonServerFeedback], Any], body: str):
            feedback = AxonServerFeedback(
                set_request_timeout=lambda timeout: pipe.send(_HandlerFeedback(timeout))
            )

            try:
                handler_ret = handler(body, feedback)
                pipe.send(handler_ret)
            except Exception as e:
                pipe.send(e)
            finally:
                pipe.close()

        parent_pipe, child_pipe = multiprocessing.Pipe()

        process = multiprocessing.Process(
            target=worker,
            args=(child_pipe, handler, body),
        )

        process.start()

        # Try to receive response.
        start_time = time.time()
        timeout = options.post_request_timeout
    
        while time.time() - start_time < timeout:
            if parent_pipe.poll(POLL_INTERVAL):
                result = parent_pipe.recv()

                # Feedback means that the handler is working properly,
                # but it needs more time to process the request.
                if isinstance(result, _HandlerFeedback):
                    timeout = result.new_timeout
                    continue

                process.join()

                if isinstance(result, Exception):
                    raise result
                else:
                    return result

        # Oh, no, handler hangs. Close pipes and start shutdown process.
        parent_pipe.close()
        child_pipe.close()

        # Try to SIGTERM it.
        process.terminate()

        # And wait some time before SIGKILL, maybe we will still be able
        # to terminate the process correctly.
        start_time = time.time()
        while time.time() - start_time < options.post_request_graceful_shutdown_timeout:
            if process.is_alive():
                time.sleep(POLL_INTERVAL)
            else:
                break

        if process.is_alive():
            process.kill()

        process.join()

        return HTTPStatus.REQUEST_TIMEOUT

    def __get_server(self) -> AxonServer:
        assert isinstance(self.server, AxonServer)
        return self.server

    def __response(self, response: HTTPStatus | str | Any | None):
        status_code = response.value if isinstance(response, HTTPStatus) else 200
        self.send_response(status_code)

        # Nothing to send, just return
        if response is None:
            self.end_headers()

        # Something happend in response processing pipeline
        elif isinstance(response, HTTPStatus):
            json_error = json.dumps({"error": response.phrase}).encode()

            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(json_error))
            self.end_headers()
            self.wfile.write(json_error)

        # Handler return string, just send as is
        elif isinstance(response, str):
            raw_response = response.encode()

            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", len(raw_response))
            self.end_headers()
            self.wfile.write(raw_response)

        # Handler return something, try to dump it to json
        else:
            json_response = json.dumps(response).encode()

            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(json_response))
            self.end_headers()
            self.wfile.write(json_response)
