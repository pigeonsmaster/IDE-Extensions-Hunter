from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ide-extension-hunter",
    version="1.0.0",
    author="Almog Mendelson",
    author_email="pigeonsmaster@proton.me",  # Replace with your email
    description="A security scanner for IDE extensions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pigeonsmaster/ide-extension-hunter",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=[
        "aiofiles>=0.7.0",
        "tabulate>=0.8.9",
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "dev": [
            "black>=22.6.0",
            "flake8>=5.0.4",
            "pytest>=7.0.0",
            "pytest-asyncio>=0.19.0",
            "pytest-cov>=3.0.0",
        ],
        "yara": ["yara-python>=4.2.0"],
    },
    entry_points={
        "console_scripts": [
            "ide-hunter=ide_hunter.__main__:main",
        ],
    },
    include_package_data=True,
)
