# Gmail MCP Server

A Gmail integration with FastMCP (Model Control Protocol) that enables AI assistants to interact with Gmail through a set of tools and prompts.

## Overview

This project provides a server-client architecture that allows AI assistants to perform Gmail operations such as:
- Sending emails
- Reading unread emails
- Viewing email content
- Moving emails to trash
- Opening emails in browser
- Marking emails as read

The system uses Google's OAuth 2.0 for authentication and the Gmail API for email operations. It now includes an LLM-powered client that understands natural language requests.

## Components

### 1. Gmail Server (`gmail_server.py`)

The core server that provides MCP tools for Gmail operations:

- **FastMCP Integration**: Uses the FastMCP framework to expose Gmail operations as tools
- **OAuth Authentication**: Handles Gmail API authentication, token management and refreshing
- **Email Operations**: Implements email sending, reading, and management functionality
- **Prompts**: Includes special prompts for email drafting and management

### 2. Smart Gmail Client (`test_gmail_server.py`)

A natural language interface to the Gmail server:

- **LLM Integration**: Uses Google's Generative AI (Gemini) to interpret user requests
- **Natural Language Understanding**: Converts plain English requests into tool calls
- **Parameter Extraction**: Automatically extracts required parameters from user queries
- **Interactive Interface**: Provides a conversational experience for managing emails
- **Comprehensive Logging**: Includes detailed logging for debugging communication

## Setup and Requirements

### Prerequisites
- Python 3.6+
- Gmail API credentials (for authentication with Gmail)
- Google Generative AI API key (for the LLM-powered client)
- Packages from requirements.txt:
  ```
  google-auth>=2.22.0
  google-auth-oauthlib>=1.0.0
  google-api-python-client>=2.95.0
  fastmcp>=0.1.0
  typing-extensions>=4.5.0
  google-generativeai>=0.1.0
  python-dotenv>=0.19.0
  ```

### Initial Setup After Cloning

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up Gmail API credentials**:
   - Go to the [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one
   - Enable the Gmail API for your project
   - Create OAuth 2.0 credentials (Desktop client type)
   - Download the credentials JSON file
   - Rename it to `credentials.json` and place it in the project root

3. **Set up Gemini API Key**:
   - Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Create a new API key
   - Create a `.env` file based on the `example.env` template:
     ```bash
     cp example.env .env
     ```
   - Add your Gemini API key to the `.env` file:
     ```
     GOOGLE_API_KEY=your_api_key_here
     ```

4. **First run will generate token**:
   - The first time you run the Gmail server, it will open a browser window
   - Log in to your Google account and grant the requested permissions
   - This will generate a `token.json` file for future authentication

### Authentication Files
The system requires several authentication files:
- `credentials.json`: OAuth client ID credentials from Google Cloud Console for Gmail API
- `token.json`: Generated token file for authenticated access to Gmail
- `.env`: Environment variables file containing your Google Generative AI API key

## Usage

### Starting the Gmail Server

Start the Gmail server:
```
python gmail_server.py --creds credentials.json --token token.json
```

The server exposes the following tools:
- `send_email`: Send emails with recipient, subject, and message
- `get_unread_emails`: Retrieve unread messages
- `read_email`: Get contents of specific emails
- `trash_email`: Move emails to trash
- `open_email`: Open emails in browser
- `mark_email_as_read`: Mark emails as read

### Using the Smart Gmail Client

The smart client allows you to interact with Gmail using natural language:

```
python test_gmail_server.py
```

#### Example Commands:
- "Send an email to [recipient] about [topic]"
- "Check my unread emails"
- "Read my most recent message"
- "Open the latest email in browser"
- "Move an email from [sender] to trash"
- "Mark my unread emails as read"

The client will:
1. Process your request using the LLM
2. Determine which Gmail operation you want to perform
3. Extract necessary parameters from your request
4. Request any missing information
5. Confirm sensitive operations before executing them
6. Execute the operation and show you the results

## Implementation Details

### Email Content Handling
- Supports parsing and decoding MIME messages
- Handles multipart messages and attachments
- Properly decodes email headers

### LLM Integration
- Uses Gemini 1.5 Flash for natural language understanding
- Converts LLM responses to structured tool calls
- Includes fallback mechanisms for handling malformed LLM responses
- Handles parameter extraction from free-form text

### Error Handling
- Comprehensive logging throughout the application
- Graceful handling of HTTP errors from Gmail API
- Fallback mechanisms when the LLM response isn't formatted as expected
- Clear error responses for client applications

## Development

### Extending the Smart Client
To add support for new Gmail operations:
1. Add the appropriate tool implementation in `gmail_server.py`
2. The smart client will automatically discover and expose the new tools
3. The LLM will learn to understand requests for the new operations from the tool descriptions

### Customizing LLM Integration
You can modify the LLM prompt in `test_gmail_server.py` to:
- Improve parameter extraction for specific use cases
- Add specialized handling for particular types of requests
- Tune the system for your specific Gmail usage patterns

## Security Note

This repository does not include credential files. Never commit your:
- `credentials.json` file
- `token.json` file
- `.env` file with API keys

These files are included in the `.gitignore` file to prevent accidental commits of sensitive information.


## Reference
https://medium.com/@jason.summer/create-a-gmail-agent-with-model-context-protocol-mcp-061059c07777
