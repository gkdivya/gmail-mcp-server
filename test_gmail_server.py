from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import asyncio
import logging
import json
import os
import sys
import subprocess
import traceback
import time
from dotenv import load_dotenv
import google.generativeai as genai
import re

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Enable detailed logging for MCP modules
logging.getLogger('mcp').setLevel(logging.INFO)
logging.getLogger('mcp.client.stdio').setLevel(logging.INFO)
logging.getLogger('mcp.client.transport').setLevel(logging.INFO)

# Load environment variables
load_dotenv()

# Configure Gemini
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY not found in environment variables. Please add it to your .env file.")

# Initialize Gemini
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')  # Use an appropriate model
logger.info("Initialized Gemini model")

def serialize_tools(tools_result):
    """Convert MCP tools to a serializable format for the LLM"""
    serialized_tools = []
    
    # Process tools from ListToolsResult
    if hasattr(tools_result, 'tools'):
        for tool in tools_result.tools:
            serialized_tool = {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.inputSchema
            }
            serialized_tools.append(serialized_tool)
    
    if not serialized_tools:
        logger.warning("No tools were returned by the server")
        
    return serialized_tools

async def llm_understand_email_request(user_request, tools):
    """Use LLM to understand which Gmail tool to use based on user request"""
    serialized_tools = serialize_tools(tools)
    
    prompt = f"""You are an email assistant that can help with Gmail operations.
You have access to the following tools:
{json.dumps(serialized_tools, indent=2)}

User request: "{user_request}"

Your task is to determine which tool should be used and extract the necessary parameters.

IMPORTANT: You must respond ONLY with a valid JSON object in the following format, with no additional text, explanation, or formatting:

{{
    "tool": "name_of_tool",
    "parameters": {{
        "param1": "value1",
        "param2": "value2"
    }},
    "reasoning": "Brief explanation of why you chose this tool and how you determined the parameters"
}}

For email reading operations that require an email_id, use "latest" if the user wants to read the latest email.

Remember: Your entire response must be a valid JSON object that can be parsed with json.loads().
"""
    
    logger.info(f"Sending prompt to LLM")
    
    try:
        response = model.generate_content(prompt)
        logger.info(f"Got response from LLM")
        
        # Try to extract JSON from the response
        response_text = response.text.strip()
        
        # Look for JSON in the response text
        json_start = response_text.find('{')
        json_end = response_text.rfind('}') + 1
        
        if json_start >= 0 and json_end > json_start:
            # Extract the JSON part
            json_text = response_text[json_start:json_end]
            logger.info(f"Extracted JSON text: {json_text}")
            
            # Parse the JSON response
            try:
                response_json = json.loads(json_text)
                return response_json
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing extracted JSON: {str(e)}")
                # Fall through to default handling
        else:
            logger.error(f"No JSON found in response: {response_text}")
        
        # If we get here, either no JSON was found or parsing failed
        # Try to identify the tool and parameters from the text
        lower_text = response_text.lower()
        
        # Determine the most likely tool based on keywords
        if any(word in lower_text for word in ["send", "email to", "write"]):
            tool = "send_email"
            # Try to extract parameters
            parameters = {}
            
            # Look for recipient
            recipient_matches = re.search(r"to\s*:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", response_text)
            if recipient_matches:
                parameters["recipient_id"] = recipient_matches.group(1)
                
            # Look for subject
            subject_matches = re.search(r"subject\s*:\s*([^\n]+)", response_text)
            if subject_matches:
                parameters["subject"] = subject_matches.group(1)
                
            return {
                "tool": tool,
                "parameters": parameters,
                "reasoning": "Extracted from non-JSON response based on keywords"
            }
        elif any(word in lower_text for word in ["read", "get", "show", "unread"]):
            if "latest" in lower_text or "recent" in lower_text:
                return {
                    "tool": "read_email",
                    "parameters": {"email_id": "latest"},
                    "reasoning": "Extracted from non-JSON response based on keywords"
                }
            else:
                return {
                    "tool": "get_unread_emails",
                    "parameters": {},
                    "reasoning": "Extracted from non-JSON response based on keywords"
                }
        else:
            # Default fallback
            return {
                "tool": "get_unread_emails",
                "parameters": {},
                "reasoning": "Default fallback for non-JSON response"
            }
            
    except Exception as e:
        logger.error(f"Error in LLM processing: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Provide a meaningful fallback
        if "send" in user_request.lower() or "email" in user_request.lower():
            return {
                "tool": "send_email",
                "parameters": {},
                "reasoning": f"Fallback based on keywords after error: {str(e)}"
            }
        else:
            return {
                "tool": "get_unread_emails",
                "parameters": {},
                "reasoning": f"Default fallback after error: {str(e)}"
            }

async def smart_gmail_client():
    """Gmail client that uses LLM to determine which tools to call"""
    logger.info("===== SMART GMAIL CLIENT =====")
    
    # Server parameters for the Gmail server
    creds_path = "./credentials.json"
    token_path = "./token.json"
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["gmail_server.py", "--creds", creds_path, "--token", token_path]
    )
    
    try:
        # Connect to server using the MCP stdio client
        logger.info("Connecting to Gmail server...")
        async with stdio_client(server_params) as (read_stream, write_stream):
            logger.info("Connected to server")
            
            # Create client session
            async with ClientSession(read_stream, write_stream) as session:
                # Initialize session
                logger.info("Initializing session...")
                await session.initialize()
                logger.info("Session initialized")
                
                # List available tools
                logger.info("Listing available tools...")
                tools_result = await asyncio.wait_for(session.list_tools(), timeout=5.0)
                
                # Main interaction loop
                while True:
                    # Get user request
                    user_request = input("\nWhat would you like to do with Gmail? (type 'exit' to quit): ")
                    
                    if user_request.lower() in ['exit', 'quit', 'q']:
                        logger.info("Exiting Gmail client")
                        break
                    
                    # Have LLM interpret the request
                    logger.info("Processing request with LLM...")
                    llm_response = await llm_understand_email_request(user_request, tools_result)
                    
                    # Extract tool and parameters
                    tool_name = llm_response.get("tool")
                    parameters = llm_response.get("parameters", {})
                    reasoning = llm_response.get("reasoning", "No reasoning provided")
                    
                    logger.info(f"LLM suggests using tool: {tool_name}")
                    logger.info(f"With parameters: {json.dumps(parameters, indent=2)}")
                    logger.info(f"Reasoning: {reasoning}")
                    
                    # Special handling for "latest" email ID
                    if tool_name in ["read_email", "trash_email", "open_email", "mark_email_as_read"] and parameters.get("email_id") == "latest":
                        logger.info("Getting latest email...")
                        unread_emails = await session.call_tool("get_unread_emails", {})
                        
                        # Extract email IDs from response
                        latest_email_id = None
                        if hasattr(unread_emails, 'content') and unread_emails.content:
                            for content in unread_emails.content:
                                if hasattr(content, 'text'):
                                    try:
                                        emails_data = json.loads(content.text)
                                        if emails_data and isinstance(emails_data, list) and len(emails_data) > 0:
                                            latest_email_id = emails_data[0].get('id')
                                            break
                                    except (json.JSONDecodeError, AttributeError):
                                        pass
                        
                        if latest_email_id:
                            logger.info(f"Found latest email ID: {latest_email_id}")
                            parameters["email_id"] = latest_email_id
                        else:
                            logger.error("No unread emails found")
                            print("No unread emails found. Please try another operation.")
                            continue
                    
                    # Confirm with user before proceeding with certain operations
                    if tool_name in ["send_email", "trash_email"]:
                        print(f"\nAbout to {tool_name.replace('_', ' ')} with parameters:")
                        for key, value in parameters.items():
                            print(f"  - {key}: {value}")
                        
                        confirm = input("Proceed? (y/n): ")
                        if confirm.lower() != 'y':
                            print("Operation cancelled.")
                            continue
                    
                    # Handle empty required parameters for send_email
                    if tool_name == "send_email":
                        required_params = ["recipient_id", "subject", "message"]
                        missing_params = [p for p in required_params if p not in parameters or not parameters[p]]
                        
                        for param in missing_params:
                            parameters[param] = input(f"Please enter {param}: ")
                    
                    # Call the appropriate tool
                    try:
                        logger.info(f"Calling tool {tool_name} with parameters: {parameters}")
                        response = await asyncio.wait_for(
                            session.call_tool(tool_name, parameters),
                            timeout=10.0
                        )
                        
                        # Process and display the response
                        result_text = "Operation completed."
                        if hasattr(response, 'content') and response.content:
                            for content in response.content:
                                if hasattr(content, 'text'):
                                    result_text = content.text
                        
                        print("\nResult:", result_text)
                        logger.info(f"Tool response: {response}")
                        
                    except asyncio.TimeoutError:
                        logger.error(f"Timeout calling {tool_name}")
                        print(f"Operation timed out. Please try again.")
                    except Exception as e:
                        logger.error(f"Error calling {tool_name}: {str(e)}")
                        logger.error(traceback.format_exc())
                        print(f"Error: {str(e)}")
    
    except asyncio.TimeoutError:
        logger.error("Timeout connecting to the server")
    except Exception as e:
        logger.error(f"Error in Gmail client: {str(e)}")
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    logger.info("========== SMART GMAIL CLIENT STARTING ==========")
    try:
        asyncio.run(smart_gmail_client())
        logger.info("========== CLIENT COMPLETED SUCCESSFULLY ==========")
    except KeyboardInterrupt:
        logger.warning("Client interrupted by user")
    except Exception as e:
        logger.error(f"Unhandled error in main: {str(e)}")
        logger.error(traceback.format_exc())
    finally:
        logger.info("Client process completed") 