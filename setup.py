from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vulnebify",
    version="1.0.3",
    packages=find_packages(exclude=["tests", "tests.*"]),
    install_requires=["requests==2.32.3", "pydantic==2.11.2"],
    entry_points={
        "console_scripts": [
            "vulnebify=vulnebify.cli:main",
        ],
    },
    author="Alex @ Vulnebify",
    author_email="contact.pypi@vulnebify.com",
    description="Python library for the Vulnebify API. Run scans, inspect hosts/domains, and fetch results with real-time updates and JSON output.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vulnebify/vulnebify-python",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
