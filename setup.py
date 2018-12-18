import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="rtfraptor",
    version="1.0.0",
    author="David Cannings",
    author_email="david@edeca.net",
    description="Dump interesting OLE parts from RTF documents by instrumenting Word",
    license="GNU Affero General Public License v3",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/edeca/rtfraptor",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': ['rtfraptor=rtfraptor.app:main'],
    },
    classifiers=[
        "Programming Language :: Python :: 2",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Environment :: Win32 (MS Windows)",
        "Operating System :: Microsoft :: Windows",
        "Development Status :: 4 - Beta",
    ],
    install_requires=[
        'winappdbg',
        'oletools',
    ],
)