import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_package.py [validator|miner]")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    
    if mode == "validator":
        from neurons.validator import run_validator
        run_validator()
    elif mode == "miner":
        from neurons.miner import run_miner
        run_miner()
    elif mode == "validator_model_server":
        from model_servers.validator import run_model_server
        run_model_server()
    elif mode == "miner_model_server":
        from model_servers.miner import run_model_server
        run_model_server()
    else:
        print(f"Unknown mode: {mode}")
        print("Available modes: validator, miner, validator_model_server, miner_model_server")
        sys.exit(1)


if __name__ == "__main__":
    main()
