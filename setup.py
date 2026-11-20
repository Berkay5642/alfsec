from setuptools import setup
setup(name="alfsec", version="7.5.0", py_modules=["alfsec"], install_requires=["cryptography","PySocks","Pillow"], entry_points={"console_scripts":["alfsec=alfsec:main"]})
