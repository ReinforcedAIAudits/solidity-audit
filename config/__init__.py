try:
    from .local import Config
except ImportError:
    from .base import BaseConfig as Config

__all__ = ['Config']
