# FastAPI Middletier Service

## Overview

This project is a FastAPI-based service that provides a RESTful API for interacting with a DynamoDB database. It includes token-based authentication using OAuth2 with JWT tokens. The service allows you to perform basic CRUD operations on items stored in DynamoDB.

## Features

- **FastAPI**: A modern, fast (high-performance), web framework for building APIs with Python 3.7+ based on standard Python type hints.
- **DynamoDB**: Integration with AWS DynamoDB for storing and retrieving data.
- **OAuth2 Authentication**: Secure endpoints with token-based authentication using JWT tokens.
- **Environment Configuration**: Use `.env` files to manage environment variables.

## Setup

### Prerequisites

- Python 3.13.1 or higher
- AWS account or LocalStack with DynamoDB setup 
- `uv` (Python package installer)

### Installation

- Make sure uv is installed.
    - `pip3 install uv`
- Make sure virtual environment is created.
    - `uv venv`
- Activate the virtual environment.
    - `source .venv/bin/activate`
- Install dependencies from requirements.txt file.
    - `uv sync`
- Start the server.
    - `./start.sh`

### Configs
You will have to set a few variables in your environment or .env file before running the application:

- The name of your dynamodb table:
    - DYNAMODB_TABLE_NAME=`"<your table name>"`
- If using LocalStack
    - AWS_ENDPOINT_URL="http://localhost:4566"
- Api Key for authentication.
    - API_KEY=`"<your api key>"`