from typing import Any
import argparse
import os
import asyncio
import logging
import base64
from email.message import EmailMessage
from email.header import decode_header
from base64 import urlsafe_b64decode
from email import message_from_bytes
import webbrowser

from mcp.server.fastmcp import FastMCP

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EMAIL_ADMIN_PROMPTS = """You are an email administrator. 
You can draft, edit, read, trash, open, and send emails.
You've been given access to a specific gmail account. 
You have the following tools available:
- Send an email (send-email)
- Retrieve unread emails (get-unread-emails)
- Read email content (read-email)
- Trash email (tras-email)
- Open email in browser (open-email)
Never send an email draft or trash an email unless the user confirms first. 
Always ask for approval if not already given.
"""

# Create an MCP server
mcp = FastMCP("Gmail Operations")

@mcp.prompt("manage-email")
async def manage_email_prompt() -> str:
    """Act like an email administrator."""
    return EMAIL_ADMIN_PROMPTS

@mcp.prompt("draft-email")
async def draft_email_prompt(content: str, recipient: str, recipient_email: str) -> str:
    """Draft an email with content and recipient."""
    return f"""Please draft an email about {content} for {recipient} ({recipient_email}).
    Include a subject line starting with 'Subject:' on the first line.
    Do not send the email yet, just draft it and ask the user for their thoughts."""

@mcp.prompt("edit-draft")
async def edit_draft_prompt(changes: str, current_draft: str) -> str:
    """Edit the existing email draft."""
    return f"""Please revise the current email draft:
    {current_draft}
    
    Requested changes:
    {changes}
    
    Please provide the updated draft."""

# Create a global GmailService instance
gmail_service = None

@mcp.tool()
async def send_email(recipient_id: str, subject: str, message: str) -> dict:
    """Send an email to the specified recipient.
    Do not use if user only asked to draft email.
    Drafts must be approved before sending.
    
    Args:
        recipient_id: Recipient email address
        subject: Email subject
        message: Email content text
        
    Returns:
        dict: Response containing status and message ID
    """
    return await gmail_service.send_email(recipient_id, subject, message)

@mcp.tool()
async def get_unread_emails() -> list[dict[str, str]] | str:
    """Get all unread emails from the inbox.
    
    Returns:
        List of unread email messages or error string
    """
    return await gmail_service.get_unread_emails()

@mcp.tool()
async def read_email(email_id: str) -> dict[str, str] | str:
    """Read the contents of a specific email.
    
    Args:
        email_id: Email ID to read
        
    Returns:
        dict: Email contents including subject, from, to, and body
    """
    return await gmail_service.read_email(email_id)

@mcp.tool()
async def trash_email(email_id: str) -> str:
    """Move an email to trash.
    Confirm before moving email to trash.
    
    Args:
        email_id: Email ID to move to trash
        
    Returns:
        str: Success or error message
    """
    return await gmail_service.trash_email(email_id)

@mcp.tool()
async def open_email(email_id: str) -> str:
    """Open an email in the browser.
    
    Args:
        email_id: Email ID to open
        
    Returns:
        str: Success or error message
    """
    return await gmail_service.open_email(email_id)

@mcp.tool()
async def mark_email_as_read(email_id: str) -> str:
    """Mark an email as read.
    
    Args:
        email_id: Email ID to mark as read
        
    Returns:
        str: Success or error message
    """
    return await gmail_service.mark_email_as_read(email_id)

@mcp.resource("operations://list")
async def list_operations() -> str:
    """List all available Gmail operations."""
    return """
    Available Gmail Operations:
    1. Send Email: Send an email to a recipient
    2. Get Unread Emails: Retrieve all unread emails from inbox
    3. Read Email: Read the contents of a specific email
    4. Trash Email: Move an email to trash
    5. Open Email: Open an email in the browser
    6. Mark Email as Read: Mark an email as read
    """

def decode_mime_header(header: str) -> str: 
    """Helper function to decode encoded email headers"""
    
    decoded_parts = decode_header(header)
    decoded_string = ''
    for part, encoding in decoded_parts: 
        if isinstance(part, bytes): 
            # Decode bytes to string using the specified encoding 
            decoded_string += part.decode(encoding or 'utf-8') 
        else: 
            # Already a string 
            decoded_string += part 
    return decoded_string

class GmailService:
    def __init__(self,
                 creds_file_path: str,
                 token_path: str,
                 scopes: list[str] = ['https://www.googleapis.com/auth/gmail.modify']):
        logger.info(f"Initializing GmailService with creds file: {creds_file_path}")
        self.creds_file_path = creds_file_path
        self.token_path = token_path
        self.scopes = scopes
        self.token = self._get_token()
        logger.info("Token retrieved successfully")
        self.service = self._get_service()
        logger.info("Gmail service initialized")
        self.user_email = self._get_user_email()
        logger.info(f"User email retrieved: {self.user_email}")

    def _get_token(self) -> Credentials:
        """Get or refresh Google API token"""

        token = None
    
        if os.path.exists(self.token_path):
            logger.info('Loading token from file')
            token = Credentials.from_authorized_user_file(self.token_path, self.scopes)

        if not token or not token.valid:
            if token and token.expired and token.refresh_token:
                logger.info('Refreshing token')
                token.refresh(Request())
            else:
                logger.info('Fetching new token')
                flow = InstalledAppFlow.from_client_secrets_file(self.creds_file_path, self.scopes)
                token = flow.run_local_server(port=8080)

            with open(self.token_path, 'w') as token_file:
                token_file.write(token.to_json())
                logger.info(f'Token saved to {self.token_path}')

        return token

    def _get_service(self) -> Any:
        """Initialize Gmail API service"""
        try:
            service = build('gmail', 'v1', credentials=self.token)
            return service
        except HttpError as error:
            logger.error(f'An error occurred building Gmail service: {error}')
            raise ValueError(f'An error occurred: {error}')
    
    def _get_user_email(self) -> str:
        """Get user email address"""
        profile = self.service.users().getProfile(userId='me').execute()
        user_email = profile.get('emailAddress', '')
        return user_email
    
    async def send_email(self, recipient_id: str, subject: str, message: str,) -> dict:
        """Creates and sends an email message"""
        try:
            message_obj = EmailMessage()
            message_obj.set_content(message)
            
            message_obj['To'] = recipient_id
            message_obj['From'] = self.user_email
            message_obj['Subject'] = subject

            encoded_message = base64.urlsafe_b64encode(message_obj.as_bytes()).decode()
            create_message = {'raw': encoded_message}
            
            send_message = await asyncio.to_thread(
                self.service.users().messages().send(userId="me", body=create_message).execute
            )
            logger.info(f"Message sent: {send_message['id']}")
            return {"status": "success", "message_id": send_message["id"]}
        except HttpError as error:
            return {"status": "error", "error_message": str(error)}

    async def open_email(self, email_id: str) -> str:
        """Opens email in browser given ID."""
        try:
            url = f"https://mail.google.com/#all/{email_id}"
            webbrowser.open(url, new=0, autoraise=True)
            return "Email opened in browser successfully."
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"

    async def get_unread_emails(self) -> list[dict[str, str]]| str:
        """
        Retrieves unread messages from mailbox.
        Returns list of messsage IDs in key 'id'."""
        try:
            user_id = 'me'
            query = 'in:inbox is:unread category:primary'

            response = self.service.users().messages().list(userId=user_id,
                                                        q=query).execute()
            messages = []
            if 'messages' in response:
                messages.extend(response['messages'])

            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = self.service.users().messages().list(userId=user_id, q=query,
                                                    pageToken=page_token).execute()
                messages.extend(response['messages'])
            return messages

        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"

    async def read_email(self, email_id: str) -> dict[str, str]| str:
        """Retrieves email contents including to, from, subject, and contents."""
        try:
            msg = self.service.users().messages().get(userId="me", id=email_id, format='raw').execute()
            email_metadata = {}

            # Decode the base64URL encoded raw content
            raw_data = msg['raw']
            decoded_data = urlsafe_b64decode(raw_data)

            # Parse the RFC 2822 email
            mime_message = message_from_bytes(decoded_data)

            # Extract the email body
            body = None
            if mime_message.is_multipart():
                for part in mime_message.walk():
                    # Extract the text/plain part
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                # For non-multipart messages
                body = mime_message.get_payload(decode=True).decode()
            email_metadata['content'] = body
            
            # Extract metadata
            email_metadata['subject'] = decode_mime_header(mime_message.get('subject', ''))
            email_metadata['from'] = mime_message.get('from','')
            email_metadata['to'] = mime_message.get('to','')
            email_metadata['date'] = mime_message.get('date','')
            
            logger.info(f"Email read: {email_id}")
            
            # We want to mark email as read once we read it
            await self.mark_email_as_read(email_id)

            return email_metadata
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
        
    async def trash_email(self, email_id: str) -> str:
        """Moves email to trash given ID."""
        try:
            self.service.users().messages().trash(userId="me", id=email_id).execute()
            logger.info(f"Email moved to trash: {email_id}")
            return "Email moved to trash successfully."
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
        
    async def mark_email_as_read(self, email_id: str) -> str:
        """Marks email as read given ID."""
        try:
            self.service.users().messages().modify(userId="me", id=email_id, body={'removeLabelIds': ['UNREAD']}).execute()
            logger.info(f"Email marked as read: {email_id}")
            return "Email marked as read."
        except HttpError as error:
            return f"An HttpError occurred: {str(error)}"
  
def main(creds_file_path: str,
           token_path: str):
    global gmail_service
    try:
        logger.info("Initializing Gmail service...")
        gmail_service = GmailService(creds_file_path, token_path)
        logger.info("Gmail service initialized successfully")
        
        # Start the server with stdio transport
        logger.info("Starting MCP server with stdio transport...")
        #logger.info("Registered tools: %s", list(mcp._tool_manager._tools))
        
        # Run the server with stdio transport
        logger.info("Starting MCP server with stdio transport...")
        try:
            # Run with simpler configuration 
            mcp.run(transport="stdio")
        except Exception as server_error:
            logger.error(f"Server error: {str(server_error)}", exc_info=True)
            raise
            
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run the Gmail MCP server')
    parser.add_argument('--creds', required=True, help='Path to credentials.json file')
    parser.add_argument('--token', required=True, help='Path to token.json file')
    args = parser.parse_args()
    
    logger.info("Starting Gmail server with args: %s", args)
    try:
        main(args.creds, args.token)
    except Exception as e:
        logger.error("Server failed with error: %s", str(e), exc_info=True)
        raise
    logger.info("Gmail server stopped")