"""Setup configuration for aicomp_sdk package."""

from pathlib import Path

from setuptools import find_packages, setup

# Read the long description from README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="aicomp-sdk",
    version="1.0.6",
    description="AI Agent Security Competition SDK - Red teaming framework for tool-using AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Competition Organizers",
    author_email="",  # Add email if available
    url="https://github.com/mbhatt1/competitionscratch",
    project_urls={
        "Bug Tracker": "https://github.com/mbhatt1/competitionscratch/issues",
        "Documentation": "https://github.com/mbhatt1/competitionscratch/blob/main/docs/README.md",
        "Source Code": "https://github.com/mbhatt1/competitionscratch",
    },
    packages=find_packages(
        exclude=[
            "tests",
            "tests.*",
            "examples",
            "examples.*",
            "scripts",
            "research",
            "docs",
        ]
    ),
    python_requires=">=3.8",
    install_requires=[
        "transformers>=4.30.0",
        "torch>=2.0.0",
        "openai>=1.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    package_data={
        "aicomp_sdk": [
            "py.typed",  # For type checking support
        ],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Education",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Typing :: Typed",
    ],
    keywords="ai security red-team guardrails llm agent-safety adversarial-ml",
    license="MIT",
    zip_safe=False,
)
