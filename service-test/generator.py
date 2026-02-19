"""
Sample generator for creating dynamic malicious test content.
Uses actual prompt-guard patterns for realistic testing.
"""

import json
import random
from dataclasses import dataclass
from typing import Optional

import templates
from templates import (
    get_random_injection,
    get_random_secret,
    get_random_pii,
    get_random_dangerous_command,
    get_random_sql_injection,
    get_random_xss,
    get_random_jailbreak,
    get_attack_templates,
    CLEAN_TEMPLATES,
)


@dataclass
class GenerationParams:
    """Parameters for generating a test sample."""
    filetype: str = "html"
    severity: str = "high"
    attack_type: str = "injection"
    obfuscated: bool = False
    lang: str = "en"
    clean: bool = False
    name: str = "test"


class Obfuscator:
    """Handles obfuscation of attack content."""

    @staticmethod
    def base64_encode(text: str) -> str:
        import base64
        return base64.b64encode(text.encode()).decode()

    @staticmethod
    def hex_encode(text: str) -> str:
        return text.encode().hex()

    @staticmethod
    def html_entities(text: str) -> str:
        import html
        return html.escape(text)

    @classmethod
    def obfuscate(cls, text: str) -> str:
        """Obfuscate text using random method."""
        method = random.choice(["base64", "hex", "html_entities"])
        if method == "base64":
            return cls.base64_encode(text)
        elif method == "hex":
            return cls.hex_encode(text)
        elif method == "html_entities":
            return cls.html_entities(text)
        return text


class SampleGenerator:
    """Generates dynamic test samples with realistic malicious content."""

    def __init__(self):
        self.obfuscator = Obfuscator()

    def generate(self, params: GenerationParams) -> str:
        """Generate a sample based on parameters."""
        if params.clean:
            return self._generate_clean(params)

        return self._generate_malicious(params)

    def _generate_clean(self, params: GenerationParams) -> str:
        """Generate clean content (should pass scanning)."""
        template = CLEAN_TEMPLATES.get(
            params.filetype, CLEAN_TEMPLATES["txt"]
        )
        return template

    def _generate_malicious(self, params: GenerationParams) -> str:
        """Generate malicious content based on parameters."""
        filetype = params.filetype

        if filetype == "html":
            return self._generate_html(params)
        elif filetype == "md":
            return self._generate_md(params)
        elif filetype == "json":
            return self._generate_json(params)
        elif filetype == "xml":
            return self._generate_xml(params)
        else:
            return self._generate_txt(params)

    def _get_attack_content(self, params: GenerationParams) -> str:
        """Get attack content based on type."""
        if params.attack_type == "injection":
            return get_random_injection(params.lang, params.severity)
        elif params.attack_type == "secret":
            return get_random_secret()
        elif params.attack_type == "pii":
            return get_random_pii()
        elif params.attack_type == "jailbreak":
            return get_random_jailbreak()
        elif params.attack_type == "sql":
            return get_random_sql_injection()
        elif params.attack_type == "xss":
            return get_random_xss()
        elif params.attack_type == "rce":
            return get_random_dangerous_command()
        else:
            return get_random_injection(params.lang, params.severity)

    def _generate_html(self, params: GenerationParams) -> str:
        """Generate HTML with embedded attacks."""
        attack_content = self._get_attack_content(params)
        
        # Get template based on severity
        templates_list = get_attack_templates("html", params.severity)
        template = random.choice(templates_list)
        
        # Encode if obfuscated
        if params.obfuscated:
            attack_content = self.obfuscator.obfuscate(attack_content)
        
        # Use safe replacement instead of .format() to avoid issues with { }
        attack_html = template.replace("{attack}", attack_content)

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Company About Page</title>
</head>
<body>
    <h1>About Our Company</h1>
    <p>We are a leading provider of innovative solutions.</p>
    
    {attack_html}
    
    <h2>Our Mission</h2>
    <p>To deliver exceptional value to our customers.</p>
    
    <h2>Contact Us</h2>
    <p>Email: info@example.com</p>
</body>
</html>"""

    def _generate_md(self, params: GenerationParams) -> str:
        """Generate Markdown with embedded attacks."""
        attack_content = self._get_attack_content(params)
        
        templates_list = get_attack_templates("md", params.severity)
        template = random.choice(templates_list)
        
        if params.obfuscated:
            attack_content = self.obfuscator.obfuscate(attack_content)
        
        attack_md = template.replace("{attack}", attack_content)

        return f"""# Project Documentation

## Overview

This project provides innovative solutions for modern challenges.

## Important

{attack_md}

## Features

- Feature one: Fast processing
- Feature two: Secure storage
- Feature three: Easy integration

## Getting Started

1. Install dependencies
2. Configure settings
3. Run the application

## Support

Contact us at support@example.com
"""

    def _generate_json(self, params: GenerationParams) -> str:
        """Generate JSON with embedded secrets/attacks."""
        if params.attack_type == "secret":
            secret = get_random_secret()
            # secret already includes field name, extract just the value part
            content = {
                "status": "success",
                "data": secret,
            }
        elif params.attack_type == "pii":
            pii = get_random_pii()
            content = {
                "status": "success",
                "user": {
                    "name": "John Doe",
                    "email": "john@example.com",
                    "ssn": "123-45-6789",
                    "phone": "555-123-4567",
                    "note": pii,
                },
            }
        else:
            attack_content = self._get_attack_content(params)
            content = {
                "status": "success",
                "message": attack_content,
                "data": {
                    "content": attack_content,
                },
            }

        json_str = json.dumps(content, indent=2)

        if params.obfuscated:
            b64 = self.obfuscator.base64_encode(json_str)
            return json.dumps({"data": b64, "_hint": "base64 encoded"})

        return json_str

    def _generate_xml(self, params: GenerationParams) -> str:
        """Generate XML with embedded attacks."""
        attack_content = self._get_attack_content(params)

        if params.obfuscated:
            attack_content = self.obfuscator.obfuscate(attack_content)

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<project>
    <name>ExampleApp</name>
    <version>1.0.0</version>
    <status>active</status>
    <data>
        <content>{attack_content}</content>
    </data>
</project>"""

    def _generate_txt(self, params: GenerationParams) -> str:
        """Generate plain text with embedded attacks."""
        attack_content = self._get_attack_content(params)

        if params.obfuscated:
            attack_content = self.obfuscator.obfuscate(attack_content)

        return f"""Project Summary

This is a text file containing normal project documentation.

Section 1: Introduction
Welcome to our project. We provide innovative solutions.

{attack_content}

Section 2: Features
- Fast processing
- Secure storage
- Easy integration

Section 3: Contact
Email: info@example.com
"""

    def get_index_html(self) -> str:
        """Generate index page with links to samples."""
        severities = ["critical", "high", "medium"]
        filetypes = ["html", "md", "json", "xml", "txt"]

        rows = []
        for severity in severities:
            for filetype in filetypes:
                url = f"/test/test?filetype={filetype}&severity={severity}"
                rows.append(f'<tr><td>{filetype}</td><td>{severity}</td><td><a href="{url}">{url}</a></td></tr>')

        return f"""<!DOCTYPE html>
<html>
<head>
    <title>Test Samples Index</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        a {{ color: #0066cc; }}
    </style>
</head>
<body>
    <h1>Prompt Defender Test Samples</h1>
    <p>Dynamic samples using actual prompt-guard patterns.</p>

    <h2>Available Samples</h2>
    <table>
        <tr>
            <th>File Type</th>
            <th>Severity</th>
            <th>URL</th>
        </tr>
        {''.join(rows)}
    </table>

    <h2>Query Parameters</h2>
    <ul>
        <li><code>filetype</code>: html, md, txt, json, xml</li>
        <li><code>severity</code>: critical, high, medium</li>
        <li><code>type</code>: injection, jailbreak, secret, pii</li>
        <li><code>obfuscated</code>: true, false</li>
        <li><code>lang</code>: en, es, fr, de, ru, ko, ja, zh</li>
        <li><code>clean</code>: true (returns clean content)</li>
    </ul>

    <h2>Example URLs</h2>
    <ul>
        <li><a href="/test/test?filetype=html&severity=critical">Critical HTML</a></li>
        <li><a href="/test/test?filetype=md&severity=high">High Markdown</a></li>
        <li><a href="/test/test?filetype=json&type=secret">JSON Secret Leak</a></li>
        <li><a href="/test/test?clean=true&filetype=html">Clean HTML</a></li>
    </ul>
</body>
</html>"""
