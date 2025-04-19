from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hhchecker",
    version="0.1.0",
    author="NonBytes",
    author_email="nonbytes@example.com",
    description="A comprehensive cybersecurity assessment toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nonbytes/hhchecker",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
    ],
    python_requires=">=3.7",
    install_requires=[
        "requests>=2.25.0",
        "colorama>=0.4.4",
        "urllib3>=1.26.5",
        "typing-extensions>=4.0.0",
        "argparse>=1.4.0",
    ],
    entry_points={
        "console_scripts": [
            "hhchecker=hhchecker.cli:main",
        ],
    },
)
