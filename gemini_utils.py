import os
from dotenv import load_dotenv
import pathlib
import textwrap
import markdown

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

BASE_PROMPT_ACTION = """
- Analyze the following static analysis report of an app and suggest the possible actions that the user should carry out based on the report findings.
- Make sure that you provide me with the best suitable action. 
- Provide no headings.
- Make sure that the action is briefly explained in maximum 2 lines as a paragraph and not separate points.
- Make sure that the action is best suited based upon the findings in the code, permissions, strings etc.
- Make sure that the action provided is feasible to do by a normal user from his mobile phone.
- Keep in mind that the user performing the action is not a software engineer and is not able to edit the app code.
- Sample report in json format
"""

BASE_PROMPT_SUMMARY = """
- Analyze the following static analysis report of an app and provide a brief summary in a not technical layman language.
- Provide no headings.
- Focus majorly on vulnerability issues.
- Make sure that the summary is briefly explained in maximum 40 words as a paragraph and not separate points.
- Make sure that the summary is understandable by a normal user who has no technical knowledge.
- Do not provide the suitable action for the user. Only summary is to be provided.
- Sample report in json format
"""