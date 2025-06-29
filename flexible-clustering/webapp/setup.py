from setuptools import setup
from Cython.Build import cythonize
import numpy

setup(
    name='flexible_clustering',
    version='0.1.0',
    description='Flexible Clustering',
    long_description=open("fish/README.rst").read(),
    packages=['fish'],
    include_dirs=[numpy.get_include()],
    ext_modules=cythonize("fish/unionfind.pyx"),
)
