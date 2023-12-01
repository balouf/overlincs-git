import os
from typing import Any, Dict

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

about: Dict[str, Any] = {}
with open(os.path.join(here, "sharelatex", "__version__.py")) as f:
    exec(f.read(), about)

setup(version=about["__version__"])
