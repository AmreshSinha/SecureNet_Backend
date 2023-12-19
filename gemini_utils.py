import os
from dotenv import load_dotenv
import pathlib
import textwrap
import markdown

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

BASE_PROMPT = """
    
"""
