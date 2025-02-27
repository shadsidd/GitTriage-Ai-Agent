import streamlit as st
import pandas as pd
import numpy as np  
import json
import os
import time
import re
import requests
from functools import wraps
from bs4 import BeautifulSoup
from github import Github, GithubException
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime


from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.models.google import Gemini

# Initialize session state variables
if 'vulnerabilities' not in st.session_state:
    st.session_state.vulnerabilities = []
if 'categorized_vulnerabilities' not in st.session_state:
    st.session_state.categorized_vulnerabilities = []
if 'triage_decisions' not in st.session_state:
    st.session_state.triage_decisions = {}
if 'model_type' not in st.session_state:
    st.session_state.model_type = "openai"  
if 'repos_list' not in st.session_state:
    st.session_state.repos_list = []
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {}  
if 'active_page' not in st.session_state:
    st.session_state.active_page = "Settings"

# Define severity color mapping for UI
SEVERITY_COLORS = {
    "Critical": "#ff0000",
    "High": "#ff6600",
    "Medium": "#ffcc00",
    "Low": "#00cc00",
    "Unknown": "#808080"
}

# Higher-order function for error handling
def with_error_handling(fallback_value=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                st.error(f"Error in {func.__name__}: {str(e)}")
                return fallback_value() if callable(fallback_value) else fallback_value
        return wrapper
    return decorator

# Repository class to centralize repository operations
class Repository:
    def __init__(self, url, github_token=None):
        self.url = url
        self.github_token = github_token
        
        # Parse repository details from URL
        parts = url.strip('/').split('/')
        if len(parts) >= 5 and parts[2] == "github.com":
            self.owner = parts[3]
            self.name = parts[4]
            self.full_name = f"{self.owner}/{self.name}"
            self.valid = True
        else:
            self.owner = "unknown"
            self.name = "unknown"
            self.full_name = "unknown/unknown"
            self.valid = False
    
    @property
    def api_url(self):
        return f"https://api.github.com/repos/{self.owner}/{self.name}"
    
    @property
    def security_url(self):
        return f"https://github.com/{self.owner}/{self.name}/security/dependabot"
    
    def get_auth_headers(self):
        if not self.github_token:
            return {}
        return {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
    
    def fetch_vulnerabilities(self):
        """Fetch vulnerabilities with fallback chain strategy."""
        if not self.valid:
            st.error("Invalid GitHub repository URL")
            return self._generate_sample_data()
        
        # Try API first, then web scraping, then fallback to samples
        vulnerabilities = self._fetch_via_api()
        if vulnerabilities:
            return vulnerabilities
            
        vulnerabilities = self._fetch_via_scraping()
        if vulnerabilities:
            return vulnerabilities
            
        return self._generate_sample_data()
    
    def _fetch_via_api(self):
        """Fetch vulnerabilities using GitHub API."""
        if not self.github_token:
            return []
            
        try:
            api_url = f"{self.api_url}/dependabot/alerts"
            headers = self.get_auth_headers()
            
            with st.spinner(f"Fetching Dependabot alerts for {self.full_name}..."):
                response = requests.get(api_url, headers=headers)
                
                if response.status_code == 200:
                    alerts_data = response.json()
                    vulnerabilities = []
                    
                    for i, alert in enumerate(alerts_data):
                        try:
                            security_advisory = alert.get("security_advisory", {})
                            dependency = alert.get("dependency", {})
                            package = dependency.get("package", {})
                            
                            vuln = {
                                "id": f"GHSA-{alert.get('number', i+1)}",
                                "name": security_advisory.get("summary", "Unknown vulnerability"),
                                "package_name": package.get("name", "Unknown"),
                                "current_version": dependency.get("version", "Unknown"),
                                "fixed_version": ", ".join(security_advisory.get("patched_versions", ["Latest"])),
                                "severity": security_advisory.get("severity", "Unknown"),
                                "description": security_advisory.get("description", "No description available"),
                                "path": dependency.get("manifest_path", "Unknown"),
                                "repo": self.full_name
                            }
                            vulnerabilities.append(vuln)
                        except Exception as e:
                            st.warning(f"Error processing alert: {str(e)}")
                    
                    if vulnerabilities:
                        st.success(f"Found {len(vulnerabilities)} Dependabot alerts")
                        return vulnerabilities
                else:
                    st.warning(f"Failed to access security information via API: HTTP {response.status_code}")
            
            return []
        except Exception as e:
            st.warning(f"API access error: {str(e)}")
            return []
    
    def _fetch_via_scraping(self):
        """Fetch vulnerabilities using web scraping."""
        if not self.github_token:
            return []
            
        try:
            st.info("Trying alternative method to fetch security alerts.")
            
            # Create a session with authentication
            session = requests.Session()
            session.headers.update(self.get_auth_headers())
            
            # Try security/dependabot page first
            response = session.get(self.security_url)
            
            # If we get a 404, try the security overview page
            if response.status_code == 404:
                security_url = f"https://github.com/{self.owner}/{self.name}/security"
                response = session.get(security_url)
            
            if response.status_code == 200:
                vulnerabilities = []
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Try different selectors to find security alerts
                selectors = [
                    '.Box-row', 
                    '[data-test-selector="security-advisory-card"]',
                    '.js-navigation-item'
                ]
                
                alert_elements = []
                for selector in selectors:
                    elements = soup.select(selector)
                    if elements:
                        alert_elements = elements
                        break
                
                # Process found elements
                for i, alert in enumerate(alert_elements):
                    try:
                        # Look for title in various elements
                        title_element = (
                            alert.select_one('a[data-hovercard-type="security_advisory"]') or 
                            alert.select_one('a.Link--primary') or
                            alert.select_one('a[href*="advisories"]')
                        )
                        
                        if not title_element:
                            continue
                        
                        title = title_element.text.strip()
                        
                        # Extract package name
                        package_name = "Unknown"
                        package_matches = re.search(r'in\s+([a-zA-Z0-9._-]+)', title)
                        if package_matches:
                            package_name = package_matches.group(1)
                        
                        # Extract severity
                        severity_element = (
                            alert.select_one('.Label--security') or 
                            alert.select_one('.Label')
                        )
                        severity = severity_element.text.strip() if severity_element else "Unknown"
                        
                        # Extract description
                        desc_element = (
                            alert.select_one('p.color-fg-muted') or 
                            alert.select_one('.color-fg-muted')
                        )
                        description = desc_element.text.strip() if desc_element else "No description available"
                        
                        vuln = {
                            "id": f"DEP-{i+1}",
                            "name": title,
                            "package_name": package_name,
                            "current_version": "Unknown",
                            "fixed_version": "Latest",
                            "severity": severity,
                            "description": description,
                            "path": "package.json",  # Default assumption
                            "repo": self.full_name
                        }
                        vulnerabilities.append(vuln)
                    except Exception as e:
                        continue
                
                if vulnerabilities:
                    st.success(f"Found {len(vulnerabilities)} vulnerabilities via web scraping")
                    return vulnerabilities
                
            return []
        except Exception as e:
            st.warning(f"Web scraping error: {str(e)}")
            return []
    
    def _generate_sample_data(self):
        """Generate sample vulnerability data."""
        sample_data = [
            {
                "id": "GHSA-xvch-5gv4-984h",
                "name": "Path Traversal in express-fileupload",
                "package_name": "express-fileupload",
                "current_version": "1.2.0",
                "fixed_version": "1.2.1",
                "severity": "Critical",
                "description": "A path traversal vulnerability exists in express-fileupload that could allow an attacker to write files outside the intended directory.",
                "path": "package.json",
                "repo": self.full_name
            },
            {
                "id": "GHSA-c2qf-rxjj-qqgw",
                "name": "Cross-Site Scripting (XSS) in markdown-it",
                "package_name": "markdown-it",
                "current_version": "12.0.4",
                "fixed_version": "12.0.6",
                "severity": "High",
                "description": "markdown-it is vulnerable to cross-site scripting attacks when processing certain malformed markdown input.",
                "path": "yarn.lock",
                "repo": self.full_name
            },
            {
                "id": "GHSA-7fh5-64p2-3v2j",
                "name": "SQL Injection in sequelize",
                "package_name": "sequelize",
                "current_version": "6.5.0",
                "fixed_version": "6.6.1",
                "severity": "High",
                "description": "Improper neutralization of special elements used in an SQL command in Sequelize could lead to SQL injection attacks.",
                "path": "package-lock.json",
                "repo": self.full_name
            },
            {
                "id": "GHSA-4jqc-8m5r-9rpr",
                "name": "Prototype Pollution in lodash",
                "package_name": "lodash",
                "current_version": "4.17.15",
                "fixed_version": "4.17.21",
                "severity": "Medium",
                "description": "Prototype pollution vulnerability in lodash allows attackers to modify the prototype of Object.",
                "path": "package.json",
                "repo": self.full_name
            },
            {
                "id": "GHSA-p6mc-m468-83gw",
                "name": "Denial of Service in ws",
                "package_name": "ws",
                "current_version": "7.4.5",
                "fixed_version": "7.4.6",
                "severity": "Medium",
                "description": "The ws package is vulnerable to denial of service attacks when processing specially crafted messages.",
                "path": "package.json",
                "repo": self.full_name
            }
        ]
        st.warning("Using sample vulnerability data for demonstration purposes.")
        return sample_data

# Model strategy pattern implementation
class ModelStrategy:
    """Base class for model creation strategies."""
    def create_model(self):
        raise NotImplementedError("Subclasses must implement create_model")

class OpenAIStrategy(ModelStrategy):
    def __init__(self, api_key):
        self.api_key = api_key
        
    def create_model(self):
        if not self.api_key:
            st.error("OpenAI API key is required")
            return None
        os.environ["OPENAI_API_KEY"] = self.api_key
        return OpenAIChat(id="gpt-4o")

class GeminiStrategy(ModelStrategy):
    def __init__(self, api_key):
        self.api_key = api_key
        
    def create_model(self):
        if not self.api_key:
            st.error("Gemini API key is required")
            return None
        os.environ["GOOGLE_API_KEY"] = self.api_key
        return Gemini(id="gemini-1.5-flash", api_key=self.api_key)

def get_model_strategy():
    """Factory method to get the appropriate model strategy based on user selection."""
    if st.session_state.model_type == "openai":
        return OpenAIStrategy(st.session_state.get('openai_key', ''))
    else:
        return GeminiStrategy(st.session_state.get('gemini_key', ''))

# Agent factory functions
def create_agent(description, instructions):
    """Generic agent creation function."""
    strategy = get_model_strategy()
    if not strategy:
        return None
    
    model = strategy.create_model()
    if not model:
        return None
    
    return Agent(
        model=model,
        description=description,
        instructions=instructions,
        markdown=True
    )

def create_scanning_agent():
    """Create a scanning agent with predefined instructions."""
    return create_agent(
        description="You are a GitHub repository scanner that analyzes code for security vulnerabilities.",
        instructions=[
            "When asked to scan a repository, you'll analyze its components for security issues.",
            "Generate a comprehensive vulnerability report in JSON format with fields: id, name, package_name, current_version, fixed_version, severity, description, path",
            "Focus on common vulnerabilities like dependency issues, SQL injection, XSS, and improper authentication."
        ]
    )

def create_categorization_agent():
    """Create a categorization agent with predefined instructions."""
    return create_agent(
        description="You are a vulnerability categorization expert.",
        instructions=[
            "Analyze each vulnerability in the provided list",
            "Categorize each by Severity (Critical, High, Medium, Low)",
            "Categorize each by Type (SQL Injection, XSS, Path Traversal, etc.)",
            "Categorize each by Impact (Data Exposure, Remote Code Execution, Denial of Service, etc.)",
            "Return a structured JSON list with fields: ID, Name, Package, Current Version, Fixed Version, Severity, Type, Impact, Description"
        ]
    )

def create_triaging_agent():
    """Create a triaging agent with predefined instructions."""
    return create_agent(
        description="You are a security expert specializing in vulnerability triage.",
        instructions=[
            "Analyze the provided vulnerability in detail",
            "Assess whether it's likely a true positive or false positive",
            "Provide a confidence score (0-100%)",
            "Recommend specific remediation steps for true positives",
            "Explain your reasoning clearly",
            "Consider factors like exploitability, impact, and implementation complexity"
        ]
    )

# JSON extraction utility
def extract_json_from_response(response):
    """Extract JSON from a response using multiple strategies."""
    # Normalize input to string
    if hasattr(response, 'content'):
        response_text = str(response.content)
    elif isinstance(response, str):
        response_text = response
    else:
        response_text = str(response)
    
    # Skip empty responses
    if not response_text or response_text.isspace():
        return []
    
    # Define extraction strategies in order of preference
    strategies = [
        # Direct JSON parsing
        lambda x: json.loads(x),
        
        # JSON in markdown code blocks
        lambda x: json.loads(re.search(r'```json\s*([\s\S]*?)\s*```', x).group(1)),
        
        # Any code blocks
        lambda x: json.loads(re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', x).group(1)),
        
        # Array patterns
        lambda x: json.loads(re.search(r'$([\s\S]*)$', x).group(0)),
        
        # Object patterns
        lambda x: json.loads(re.search(r'\{([\s\S]*)\}', x).group(0)),
    ]
    
    # Try each strategy in order
    for strategy in strategies:
        try:
            result = strategy(response_text)
            if result:
                return result
        except (json.JSONDecodeError, AttributeError, TypeError, IndexError):
            continue
    
    # If all fail, try one more approach - clean and try again
    try:
        # Clean the text and look for JSON-like patterns
        cleaned_text = re.sub(r'[\n\r\t]', ' ', response_text)
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text)
        
        json_pattern = r'(\{[^{}]*\}|$[^$$]*$)'
        matches = re.findall(json_pattern, cleaned_text)
        
        for match in matches:
            try:
                result = json.loads(match)
                if result:
                    return result
            except:
                continue
    except:
        pass
    
    # If we get here, parsing failed
    st.error("Failed to parse JSON from response")
    st.code(response_text[:500] + "..." if len(response_text) > 500 else response_text)
    return []

# Cached GitHub repository fetching
@st.cache_data(ttl=3600)
def fetch_github_repositories(token):
    """Cached function to fetch GitHub repositories."""
    if not token:
        st.error("GitHub API token is required")
        return []
    
    try:
        github = Github(token)
        user = github.get_user()
        repos = []
        
        # Fetch both owned and accessible repositories
        for repo in user.get_repos():
            repos.append({
                "name": repo.full_name,
                "url": repo.html_url,
                "visibility": repo.visibility,
                "type": "owned" if repo.owner.login == user.login else "collaborator"
            })
        
        return repos
    
    except GithubException as e:
        st.error(f"GitHub API error: {str(e)}")
        return []
    
    except Exception as e:
        st.error(f"Error fetching repositories: {str(e)}")
        return []

# Repository scanning functions
@with_error_handling([])
def scan_repository(agent, repo_url):
    """Scan a repository using an AI agent."""
    repo = Repository(repo_url, st.session_state.get('github_key', ''))
    
    if not repo.valid:
        st.error("Invalid GitHub repository URL")
        return repo._generate_sample_data()
    
    st.write(f"Scanning repository {repo.full_name} for vulnerabilities...")
    
    # If no agent is provided, use repository's built-in methods
    if not agent:
        return repo.fetch_vulnerabilities()
    
    # Generate a sample vulnerability list to guide the AI
    sample_vulnerabilities = repo._generate_sample_data()[:2]  # Just use 2 samples for guidance
    
    # Compose the prompt
    prompt = f"""
    Analyze the GitHub repository at {repo_url} (owner: {repo.owner}, repo: {repo.name}) for potential security vulnerabilities.
    
    To simulate a real scan, consider these example vulnerabilities that might be found:
    {json.dumps(sample_vulnerabilities, indent=2)}
    
    Based on this information and your security knowledge, provide a comprehensive vulnerability report 
    in JSON format. Each vulnerability should include: id, name, package_name, current_version, 
    fixed_version, severity, description, and path.
    
    Return only the JSON output without any additional text.
    """
    
    # Run the agent
    with st.spinner(f"AI agent scanning repository {repo.full_name}..."):
        response = agent.run(prompt)
        vulnerabilities = extract_json_from_response(response)
        
        if not vulnerabilities:
            st.warning("No valid vulnerability data was returned from the scan. Using sample data instead.")
            vulnerabilities = sample_vulnerabilities
        
        # Add repository info to each vulnerability
        for vuln in vulnerabilities:
            if "repo" not in vuln:
                vuln["repo"] = repo.full_name
        
        st.success(f"Scan complete! Found {len(vulnerabilities)} potential vulnerabilities.")
        return vulnerabilities

@with_error_handling([])
def categorize_vulnerabilities(agent, vulnerabilities):
    """Categorize vulnerabilities using an AI agent."""
    if not vulnerabilities:
        return []
        
    if not agent:
        # Create default categorization if agent isn't available
        categorized = []
        for vuln in vulnerabilities:
            categorized.append({
                "ID": vuln.get("id", "Unknown"),
                "Name": vuln.get("name", "Unknown"),
                "Package": vuln.get("package_name", "Unknown"),
                "Current Version": vuln.get("current_version", "Unknown"),
                "Fixed Version": vuln.get("fixed_version", "Unknown"),
                "Severity": vuln.get("severity", "Unknown"),
                "Type": "Dependency",  # Default
                "Impact": "Security Vulnerability",  # Default
                "Description": vuln.get("description", "No description available"),
                "Repo": vuln.get("repo", "Unknown")
            })
        return categorized
    
    st.write("Categorizing vulnerabilities...")
    
    # Prepare the prompt with vulnerability data
    prompt = f"""
    Categorize each of the following vulnerabilities by their Severity, Type, and Impact:
    
    {json.dumps(vulnerabilities, indent=2)}
    
    Return a JSON list with each vulnerability categorized. Include fields: ID, Name, Package, Current Version, Fixed Version, Severity, Type, Impact, Description, Repo.
    """
    
    with st.spinner("AI agent categorizing vulnerabilities..."):
        response = agent.run(prompt)
        categorized_vulnerabilities = extract_json_from_response(response)
        
        if not categorized_vulnerabilities:
            # Create default categorization
            categorized_vulnerabilities = []
            for vuln in vulnerabilities:
                categorized_vulnerabilities.append({
                    "ID": vuln.get("id", "Unknown"),
                    "Name": vuln.get("name", "Unknown"),
                    "Package": vuln.get("package_name", "Unknown"),
                    "Current Version": vuln.get("current_version", "Unknown"),
                    "Fixed Version": vuln.get("fixed_version", "Unknown"),
                    "Severity": vuln.get("severity", "Unknown"),
                    "Type": "Dependency",  # Default
                    "Impact": "Security Vulnerability",  # Default
                    "Description": vuln.get("description", "No description available"),
                    "Repo": vuln.get("repo", "Unknown")
                })
        
        # Ensure each vulnerability has a repo field
        for v in categorized_vulnerabilities:
            if "Repo" not in v and "repo" not in v:
                # Try to find original vulnerability to get repo
                original = next((x for x in vulnerabilities if x.get("id") == v.get("ID") or x.get("name") == v.get("Name")), None)
                if original and "repo" in original:
                    v["Repo"] = original["repo"]
                else:
                    v["Repo"] = "Unknown"
        
        st.success("Categorization complete!")
        return categorized_vulnerabilities

@with_error_handling({})
def triage_vulnerability(agent, vulnerability):
    """Triage a specific vulnerability using an AI agent."""
    if not agent:
        return {
            "assessment": "Potentially True Positive",
            "confidence": 50,
            "remediation_steps": [
                f"Update {vulnerability.get('Package', 'the vulnerable package')} to version {vulnerability.get('Fixed Version', 'the latest version')} or later",
                "Run a security scan to verify the vulnerability has been addressed",
                "Review code that interacts with this package for any additional security issues"
            ],
            "reasoning": "Default assessment based on package information. Further analysis recommended."
        }
    
    st.write(f"Triaging vulnerability: {vulnerability.get('Name', 'Unknown')}")
    
    # Prepare the prompt with vulnerability data
    prompt = f"""
    Perform a detailed triage analysis on this vulnerability:
    
    {json.dumps(vulnerability, indent=2)}
    
    Assess whether it's likely a true positive or false positive.
    Provide a confidence score (0-100%).
    Recommend specific remediation steps.
    Explain your reasoning clearly.
    
    Format your response as JSON with the following structure:
    {{
        "assessment": "True Positive/False Positive",
        "confidence": 85,
        "remediation_steps": ["Step 1", "Step 2", ...],
        "reasoning": "Detailed explanation..."
    }}
    """
    
    with st.spinner("AI agent triaging vulnerability..."):
        response = agent.run(prompt)
        triage_result = extract_json_from_response(response)
        
        if not triage_result:
            # Return default assessment
            return {
                "assessment": "Potentially True Positive",
                "confidence": 50,
                "remediation_steps": [
                    f"Update {vulnerability.get('Package', 'the vulnerable package')} to version {vulnerability.get('Fixed Version', 'the latest version')} or later",
                    "Run a security scan to verify the vulnerability has been addressed",
                    "Review code that interacts with this package for any additional security issues"
                ],
                "reasoning": "Default assessment based on package information. Further analysis recommended."
            }
        
        return triage_result

# Multi-repository scanning pipeline
def scan_multiple_repositories(repos, use_ai=True):
    """Scan multiple repositories using a pipeline approach."""
    if not repos:
        st.error("No repositories to scan")
        return {}
    
    results = {}
    categorized_results = {}
    
    # Setup progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    total_repos = len(repos)
    scanning_agent = create_scanning_agent() if use_ai else None
    categorization_agent = create_categorization_agent() if use_ai else None
    
    for i, repo_data in enumerate(repos):
        repo_url = repo_data.get("url", "")
        repo_name = repo_data.get("name", "Unknown")
        
        # Update progress
        progress = (i) / total_repos
        progress_bar.progress(progress)
        status_text.text(f"Scanning {repo_name} ({i+1}/{total_repos})...")
        
        # Create repository object
        repo = Repository(repo_url, st.session_state.get('github_key', ''))
        
        # Scan repository
        if use_ai and scanning_agent:
            vulnerabilities = scan_repository(scanning_agent, repo_url)
        else:
            vulnerabilities = repo.fetch_vulnerabilities()
        
        # Store raw results
        results[repo_url] = vulnerabilities
        
        # Categorize vulnerabilities if AI is enabled
        if use_ai and categorization_agent and vulnerabilities:
            categorized = categorize_vulnerabilities(categorization_agent, vulnerabilities)
            categorized_results[repo_url] = categorized
        else:
            # Create basic categorization without AI
            categorized = []
            for vuln in vulnerabilities:
                categorized.append({
                    "ID": vuln.get("id", "Unknown"),
                    "Name": vuln.get("name", "Unknown"),
                    "Package": vuln.get("package_name", "Unknown"),
                    "Current Version": vuln.get("current_version", "Unknown"),
                    "Fixed Version": vuln.get("fixed_version", "Unknown"),
                    "Severity": vuln.get("severity", "Unknown"),
                    "Type": "Dependency",  # Default
                    "Impact": "Security Vulnerability",  # Default 
                    "Description": vuln.get("description", "No description available"),
                    "Repo": vuln.get("repo", "Unknown")
                })
            categorized_results[repo_url] = categorized
    
    # Complete progress bar
    progress_bar.progress(1.0)
    status_text.text("Scan completed!")
    
    # Combine all vulnerabilities into a flat list for dashboard
    all_categorized_vulnerabilities = []
    for repo_url, vulns in categorized_results.items():
        all_categorized_vulnerabilities.extend(vulns)
    
    # Update session state with all results
    st.session_state.scan_results = results
    st.session_state.categorized_vulnerabilities = all_categorized_vulnerabilities
    
    time.sleep(1)  # Give time for the user to see the completion message
    
    return results

# UI Components
def vulnerability_card(vuln, on_click=None):
    """Reusable UI component for vulnerability display."""
    with st.container():
        cols = st.columns([3, 2, 1])
        with cols[0]:
            st.markdown(f"**{vuln.get('Name', vuln.get('name', 'Unknown'))}**")
        with cols[1]:
            severity = vuln.get('Severity', vuln.get('severity', 'Unknown'))
            st.markdown(f"<span style='color:{SEVERITY_COLORS.get(severity, '#808080')};'>{severity}</span>", 
                       unsafe_allow_html=True)
        with cols[2]:
            if on_click and st.button("Details", key=f"btn_{vuln.get('ID', vuln.get('id', 'unknown'))}"):
                on_click(vuln)

# Page navigation system
def navigate_to(page_name):
    """Navigate to a different page in the app."""
    st.session_state.active_page = page_name
    st.rerun()

# Page implementations
def settings_page():
    """Settings page implementation."""
    st.header("Settings")
    
    # Model selection
    st.subheader("AI Model Selection")
    model_options = ["OpenAI", "Google Gemini"]
    selected_model = st.selectbox(
        "Select AI model to use:", 
        model_options,
        index=0 if st.session_state.model_type == "openai" else 1
    )
    
    st.session_state.model_type = "openai" if selected_model == "OpenAI" else "gemini"
    
    # API Keys
    st.subheader("API Keys")
    
    # OpenAI API Key
    openai_key = st.text_input(
        "OpenAI API Key:", 
        value=st.session_state.get('openai_key', ''),
        type="password"
    )
    st.session_state.openai_key = openai_key
    
    # Google Gemini API Key
    gemini_key = st.text_input(
        "Google Gemini API Key:", 
        value=st.session_state.get('gemini_key', ''),
        type="password"
    )
    st.session_state.gemini_key = gemini_key
    
    # GitHub API Key
    github_key = st.text_input(
        "GitHub API Key:", 
        value=st.session_state.get('github_key', ''),
        type="password",
        help="GitHub Personal Access Token with repo and security_events permissions"
    )
    st.session_state.github_key = github_key
    
    # Test connections
    st.subheader("Connection Test")
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Test AI Model Connection"):
            strategy = get_model_strategy()
            if not strategy:
                st.error("API key required for selected model.")
            else:
                with st.spinner("Testing connection..."):
                    try:
                        model = strategy.create_model()
                        if not model:
                            st.error("Failed to initialize model. Check API key.")
                        else:
                            agent = Agent(model=model, description="Test agent", instructions=["Respond with 'OK'"])
                            response = agent.run("Respond with OK to test the connection.")
                            if "OK" in str(response):
                                st.success("Connection successful!")
                            else:
                                st.warning("Got response but not expected format. API key may be valid but check quota.")
                    except Exception as e:
                        st.error(f"Connection failed: {str(e)}")
    
    with col2:
        if st.button("Test GitHub Connection"):
            if not github_key:
                st.error("GitHub API key required")
            else:
                with st.spinner("Testing connection..."):
                    try:
                        g = Github(github_key)
                        user = g.get_user()
                        st.success(f"Connected to GitHub as: {user.login}")
                    except Exception as e:
                        st.error(f"GitHub connection failed: {str(e)}")
    
    # Fetch repositories button
    if github_key:
        if st.button("Fetch GitHub Repositories"):
            with st.spinner("Fetching repositories..."):
                repos = fetch_github_repositories(github_key)
                st.session_state.repos_list = repos
                if repos:
                    st.success(f"Found {len(repos)} repositories!")
                else:
                    st.error("No repositories found or access denied")
    else:
        st.info("Add GitHub API key to fetch repositories")
    
    # Show currently loaded repositories
    if st.session_state.repos_list:
        st.subheader(f"Loaded Repositories ({len(st.session_state.repos_list)})")
        
        # Create a dataframe for better display
        repo_df = pd.DataFrame(st.session_state.repos_list)
        st.dataframe(
            repo_df[['name', 'visibility', 'type']],
            use_container_width=True,
            column_config={
                "name": "Repository Name",
                "visibility": "Visibility",
                "type": "Type"
            }
        )

def scanner_page():
    """Vulnerability scanner page implementation."""
    st.header("Vulnerability Scanner")
    
    if not st.session_state.get('github_key'):
        st.warning("GitHub API key is required. Please configure it in Settings.")
        if st.button("Go to Settings"):
            navigate_to("Settings")
        return
    
    if not st.session_state.repos_list:
        if st.button("Fetch GitHub Repositories"):
            fetch_github_repositories(st.session_state.github_key)
    
    # Repository selection
    if st.session_state.repos_list:
        # Create options for selectbox - include type/visibility info
        repo_options = [f"{repo['name']} ({repo['visibility']}, {repo['type']})" for repo in st.session_state.repos_list]
        repo_options.insert(0, "--- Select a repository ---")
        
        selected_repo_idx = st.selectbox(
            "Select a repository to scan:",
            options=range(len(repo_options)),
            format_func=lambda x: repo_options[x]
        )
        
        # Option to scan multiple repositories
        st.markdown("### Batch Scanning")
        
        selected_repos = st.multiselect(
            "Select multiple repositories to scan:",
            options=[repo['name'] for repo in st.session_state.repos_list]
        )
        
        col1, col2 = st.columns(2)
        with col1:
            use_ai = st.checkbox("Use AI for scanning", value=True, help="Use AI to analyze code. If disabled, only Dependabot alerts will be shown (or samples if none found).")
        
        with col2:
            if selected_repos and st.button("Scan Selected Repositories"):
                # Get full repo data for selected repos
                repos_to_scan = [repo for repo in st.session_state.repos_list if repo['name'] in selected_repos]
                scan_multiple_repositories(repos_to_scan, use_ai)
                navigate_to("Dashboard")
        
        # Manual URL input
        st.markdown("### Manual Repository")
        manual_url = st.text_input(
            "Or enter a GitHub repository URL directly:",
            placeholder="https://github.com/owner/repo"
        )
        
        if manual_url:
            if st.button("Scan Repository", key="scan_manual"):
                scanning_agent = create_scanning_agent() if use_ai else None
                vulnerabilities = scan_repository(scanning_agent, manual_url)
                st.session_state.vulnerabilities = vulnerabilities
                
                # Categorize vulnerabilities
                categorization_agent = create_categorization_agent() if use_ai else None
                categorized_vulnerabilities = categorize_vulnerabilities(categorization_agent, vulnerabilities)
                st.session_state.categorized_vulnerabilities = categorized_vulnerabilities
                
                # Navigate to dashboard
                navigate_to("Dashboard")
    else:
        # No repos available
        st.warning("No repositories found. Please configure your GitHub API key in Settings and fetch repositories.")

def dashboard_page():
    """Dashboard page implementation."""
    st.header("Security Vulnerability Dashboard")
    
    # Check if we have vulnerability data
    if not st.session_state.categorized_vulnerabilities:
        st.info("No vulnerability data available. Please scan a repository first.")
        if st.button("Go to Scanner"):
            navigate_to("Vulnerability Scanner")
        return
    
    # Convert to DataFrame for easier handling
    vulnerabilities_df = pd.DataFrame(st.session_state.categorized_vulnerabilities)
    
    # Create tabs for different views
    tab1, tab2, tab3 = st.tabs(["Summary", "Vulnerabilities", "Visualizations"])
    
    with tab1:
        st.subheader("Overview")
        
        # Calculate summary metrics
        total_vulns = len(vulnerabilities_df)
        
        # Create columns for metrics
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Vulnerabilities", total_vulns)
        
        with col2:
            if "Severity" in vulnerabilities_df.columns:
                critical_count = vulnerabilities_df[vulnerabilities_df["Severity"] == "Critical"].shape[0]
                high_count = vulnerabilities_df[vulnerabilities_df["Severity"] == "High"].shape[0]
                st.metric("Critical Vulnerabilities", critical_count, delta=f"{critical_count/total_vulns*100:.1f}%" if total_vulns > 0 else "0%")
        
        with col3:
            if "Severity" in vulnerabilities_df.columns:
                st.metric("High Vulnerabilities", high_count, delta=f"{high_count/total_vulns*100:.1f}%" if total_vulns > 0 else "0%")
        
        st.subheader("Repository Summary")
        
        # Create repository summary
        if "Repo" in vulnerabilities_df.columns:
            repo_summary = vulnerabilities_df.groupby("Repo").agg({
                "ID": "count",
            }).reset_index()
            
            repo_summary.columns = ["Repository", "Total Vulnerabilities"]
            
            # Add critical count if available
            if "Severity" in vulnerabilities_df.columns:
                critical_by_repo = vulnerabilities_df[vulnerabilities_df["Severity"] == "Critical"].groupby("Repo").size().reset_index()
                critical_by_repo.columns = ["Repository", "Critical Issues"]
                repo_summary = repo_summary.merge(critical_by_repo, on="Repository", how="left")
                repo_summary["Critical Issues"] = repo_summary["Critical Issues"].fillna(0).astype(int)
            
            # Add vulnerability type count if available
            if "Type" in vulnerabilities_df.columns:
                type_counts = vulnerabilities_df.groupby("Repo")["Type"].nunique().reset_index()
                type_counts.columns = ["Repository", "Vulnerability Types"]
                repo_summary = repo_summary.merge(type_counts, on="Repository", how="left")
            
            # Sort by total vulnerabilities
            repo_summary = repo_summary.sort_values("Total Vulnerabilities", ascending=False)
            
            st.dataframe(repo_summary, use_container_width=True)
    
    with tab2:
        st.subheader("Detailed Vulnerability List")
        
        # Filter options
        st.markdown("### Filter Options")
        filter_col1, filter_col2, filter_col3 = st.columns(3)
        
        # Create filter dictionaries
        filters = {}
        
        with filter_col1:
            # Severity filter
            if "Severity" in vulnerabilities_df.columns:
                severity_options = vulnerabilities_df["Severity"].unique().tolist()
                filters["Severity"] = st.multiselect("Filter by Severity", severity_options, default=severity_options)
        
        with filter_col2:
            # Type filter
            if "Type" in vulnerabilities_df.columns:
                type_options = vulnerabilities_df["Type"].unique().tolist()
                filters["Type"] = st.multiselect("Filter by Type", type_options, default=type_options)
        
        with filter_col3:
            # Repository filter
            if "Repo" in vulnerabilities_df.columns:
                repo_options = vulnerabilities_df["Repo"].unique().tolist()
                filters["Repo"] = st.multiselect("Filter by Repository", repo_options, default=repo_options)
        
        # Text search
        search_query = st.text_input("Search vulnerabilities:", placeholder="Enter package name, description, etc.")
        
        # Apply filters
        filtered_df = vulnerabilities_df.copy()
        
        for column, values in filters.items():
            if values:
                filtered_df = filtered_df[filtered_df[column].isin(values)]
        
        # Apply text search if provided
        if search_query:
            # Create a combined text column for searching across multiple fields
            search_cols = ["Name", "Package", "Description", "Type", "ID"] 
            search_cols = [col for col in search_cols if col in filtered_df.columns]
            
            # Convert all to string and combine
            for col in search_cols:
                filtered_df[col] = filtered_df[col].astype(str)
            
            # Filter rows that match the search query in any of the specified columns
            mask = filtered_df[search_cols].apply(lambda row: row.str.contains(search_query, case=False).any(), axis=1)
            filtered_df = filtered_df[mask]
        
        # Display the filtered dataframe
        if not filtered_df.empty:
            # Sort by severity (assuming Critical is most important)
            if "Severity" in filtered_df.columns:
                severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
                filtered_df["_severity_order"] = filtered_df["Severity"].map(severity_order).fillna(5)
                filtered_df = filtered_df.sort_values("_severity_order")
                filtered_df = filtered_df.drop("_severity_order", axis=1)
            
            # Display vulnerabilities
            st.write(f"Showing {len(filtered_df)} of {len(vulnerabilities_df)} vulnerabilities")
            
            # Use expanders to show details
            for _, vuln in filtered_df.iterrows():
                with st.expander(f"{vuln.get('Name', 'Unknown')} - {vuln.get('Severity', 'Unknown')} ({vuln.get('Package', 'Unknown')})"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**ID:** {vuln.get('ID', 'Unknown')}")
                        st.markdown(f"**Package:** {vuln.get('Package', 'Unknown')}")
                        st.markdown(f"**Current Version:** {vuln.get('Current Version', 'Unknown')}")
                        st.markdown(f"**Fixed Version:** {vuln.get('Fixed Version', 'Unknown')}")
                    
                    with col2:
                        st.markdown(f"**Type:** {vuln.get('Type', 'Unknown')}")
                        st.markdown(f"**Impact:** {vuln.get('Impact', 'Unknown')}")
                        st.markdown(f"**Repository:** {vuln.get('Repo', 'Unknown')}")
                    
                    st.markdown("**Description:**")
                    st.info(vuln.get('Description', 'No description available'))
                    
                    # Option to triage this vulnerability
                    if st.button("Triage This Vulnerability", key=f"triage_{vuln.get('ID', 'unknown')}"):
                        st.session_state.selected_vuln_for_triage = vuln.to_dict() if hasattr(vuln, 'to_dict') else vuln
                        navigate_to("Auto-Triage Console")
        else:
            st.info("No vulnerabilities match the current filters")
        
        # Option to go to triage console
        st.markdown("---")
        if st.button("Go to Auto-Triage Console"):
            navigate_to("Auto-Triage Console")
    
    with tab3:
        st.subheader("Interactive Visualizations")
        
        vis_type = st.selectbox(
            "Select Visualization Type:",
            ["Severity Distribution by Repository", "Vulnerability Types Distribution", "Package Risk Heatmap"]
        )
        
        if vis_type == "Severity Distribution by Repository":
            if "Repo" in vulnerabilities_df.columns and "Severity" in vulnerabilities_df.columns:
                # Group by Repo and Severity
                repo_severity = vulnerabilities_df.groupby(["Repo", "Severity"]).size().reset_index(name="Count")
                
                # Create grouped bar chart
                fig = px.bar(
                    repo_severity,
                    x="Repo",
                    y="Count",
                    color="Severity",
                    title="Vulnerability Severity Distribution by Repository",
                    color_discrete_map={
                        "Critical": "#ff0000",
                        "High": "#ff8c00",
                        "Medium": "#ffd700",
                        "Low": "#9acd32",
                        "Unknown": "#808080"
                    },
                    height=500
                )
                
                fig.update_layout(
                    xaxis_title="Repository",
                    yaxis_title="Number of Vulnerabilities",
                    legend_title="Severity"
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Repository or Severity data not available for this visualization")
        
        elif vis_type == "Vulnerability Types Distribution":
            if "Type" in vulnerabilities_df.columns:
                # Group by Type
                type_counts = vulnerabilities_df["Type"].value_counts().reset_index()
                type_counts.columns = ["Type", "Count"]
                
                # Create pie chart
                fig = px.pie(
                    type_counts,
                    values="Count",
                    names="Type",
                    title="Vulnerability Type Distribution",
                    hole=0.4
                )
                
                fig.update_layout(height=500)
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Vulnerability Type data not available for this visualization")
        
        elif vis_type == "Package Risk Heatmap":
            if "Package" in vulnerabilities_df.columns and "Severity" in vulnerabilities_df.columns:
                # Get top packages by vulnerability count
                top_packages = vulnerabilities_df["Package"].value_counts().nlargest(10).index.tolist()
                
                # Filter DataFrame to include only top packages
                top_df = vulnerabilities_df[vulnerabilities_df["Package"].isin(top_packages)]
                
                # Create a pivot table of package vs severity
                pivot_data = pd.crosstab(top_df["Package"], top_df["Severity"])
                
                # Convert to format needed for heatmap
                heatmap_data = []
                for package in pivot_data.index:
                    for severity in pivot_data.columns:
                        heatmap_data.append({
                            "Package": package,
                            "Severity": severity,
                            "Count": pivot_data.loc[package, severity]
                        })
                
                heatmap_df = pd.DataFrame(heatmap_data)
                
                # Create heatmap
                fig = px.density_heatmap(
                    heatmap_df,
                    x="Package",
                    y="Severity",
                    z="Count",
                    title="Package Risk Heatmap",
                    height=500,
                    color_continuous_scale="Reds"
                )
                
                fig.update_layout(
                    xaxis_title="Package",
                    yaxis_title="Severity",
                    coloraxis_colorbar_title="Vulnerability Count"
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Package or Severity data not available for this visualization")
        
        # Add timeframe selector for simulated time data
        st.markdown("### Time Analysis (Simulated)")
        timeframe = st.selectbox(
            "Select Timeframe:",
            ["Last 7 Days", "Last 30 Days", "Last 3 Months", "Last Year"]
        )
        
        # Generate simulated time series data
        end_date = datetime.now()
        if timeframe == "Last 7 Days":
            days = 7
        elif timeframe == "Last 30 Days":
            days = 30
        elif timeframe == "Last 3 Months":
            days = 90
        else:
            days = 365
        
        # Create synthetic time data (in a real app, this would come from actual timestamps)
        dates = pd.date_range(end=end_date, periods=min(days, 30), freq='D')
        
        # Generate data based on actual vulnerability types if available
        if "Type" in vulnerabilities_df.columns:
            types = vulnerabilities_df["Type"].unique()
            
            data = []
            for t in types:
                for d in dates:
                    # Updated random count generation
                    count = int(5 + 5 * (d - dates[0]).days / (dates[-1] - dates[0]).days + np.random.randint(0, 5))
                    data.append({"Type": t, "Date": d, "Count": count})
            
            time_df = pd.DataFrame(data)
            
            # Create line chart
            fig = px.line(
                time_df,
                x="Date",
                y="Count",
                color="Type",
                title="Vulnerability Types Over Time (Simulated)",
                height=500
            )
            
            fig.update_layout(
                xaxis_title="Date",
                yaxis_title="Number of Vulnerabilities",
                legend_title="Vulnerability Type"
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Vulnerability Type data not available for time analysis visualization")

def triage_console_page():
    """Auto-triage console page implementation."""
    st.header("Vulnerability Auto-Triage Console")
    
    # Check if we have a vulnerability selected for triage
    selected_vuln = st.session_state.get('selected_vuln_for_triage')
    
    # If we have vulnerabilities but none selected, show selection interface
    if not selected_vuln and st.session_state.categorized_vulnerabilities:
        st.subheader("Select a Vulnerability to Triage")
        
        # Convert to DataFrame for filtering
        vulnerabilities_df = pd.DataFrame(st.session_state.categorized_vulnerabilities)
        
        # Add filters
        severity_filter = st.multiselect(
            "Filter by Severity", 
            options=vulnerabilities_df["Severity"].unique() if "Severity" in vulnerabilities_df.columns else [],
            default=vulnerabilities_df["Severity"].unique() if "Severity" in vulnerabilities_df.columns else []
        )
        
        # Apply filters
        if severity_filter:
            filtered_df = vulnerabilities_df[vulnerabilities_df["Severity"].isin(severity_filter)]
        else:
            filtered_df = vulnerabilities_df
        
        # Display vulnerabilities as selectable cards
        for i, vuln in enumerate(filtered_df.to_dict('records')):
            with st.container():
                cols = st.columns([4, 2, 1])
                with cols[0]:
                    st.write(f"**{vuln.get('Name', 'Unknown')}**")
                with cols[1]:
                    severity = vuln.get('Severity', 'Unknown')
                    st.markdown(f"<span style='color:{SEVERITY_COLORS.get(severity, '#808080')};'>{severity}</span>", 
                            unsafe_allow_html=True)
                with cols[2]:
                    if st.button("Triage", key=f"select_{i}"):
                        st.session_state.selected_vuln_for_triage = vuln
                        st.rerun()
        
        # Option to return to dashboard
        if st.button("Return to Dashboard"):
            navigate_to("Dashboard")
        
        return
    
    # If no vulnerabilities are available, show message
    if not st.session_state.categorized_vulnerabilities:
        st.info("No vulnerabilities available for triage. Please scan a repository first.")
        if st.button("Go to Scanner"):
            navigate_to("Vulnerability Scanner")
        return
    
    # Display the selected vulnerability for triage
    if selected_vuln:
        st.subheader(f"Triaging: {selected_vuln.get('Name', 'Unknown Vulnerability')}")
        
        # Create a card-like display for the vulnerability
        st.markdown("### Vulnerability Details")
        
        # Use columns for layout
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**Package:** {selected_vuln.get('Package', 'Unknown')}")
            st.markdown(f"**Current Version:** {selected_vuln.get('Current Version', 'Unknown')}")
            st.markdown(f"**Fixed Version:** {selected_vuln.get('Fixed Version', 'Unknown')}")
        
        with col2:
            severity = selected_vuln.get('Severity', 'Unknown')
            st.markdown(f"**Severity:** <span style='color:{SEVERITY_COLORS.get(severity, '#808080')};'>{severity}</span>", unsafe_allow_html=True)
            st.markdown(f"**Type:** {selected_vuln.get('Type', 'Unknown')}")
            st.markdown(f"**Impact:** {selected_vuln.get('Impact', 'Unknown')}")
        
        st.markdown("**Description:**")
        st.info(selected_vuln.get('Description', 'No description available'))
        
        # Check if we already have triage results
        vuln_id = selected_vuln.get('ID', selected_vuln.get('id', 'unknown-id'))
        
        if vuln_id in st.session_state.triage_decisions:
            triage_result = st.session_state.triage_decisions[vuln_id]
            
            st.success("Triage Analysis Complete")
            
            # Display triage results in a nice format
            result_col1, result_col2 = st.columns(2)
            with result_col1:
                assessment = triage_result.get('assessment', 'Unknown')
                assessment_color = "#ff0000" if "false" in assessment.lower() else "#00cc00" if "true" in assessment.lower() else "#808080"
                st.markdown(f"**Assessment:** <span style='color:{assessment_color};'>{assessment}</span>", unsafe_allow_html=True)
            
            with result_col2:
                confidence = triage_result.get('confidence', 0)
                confidence_color = "#00cc00" if confidence > 80 else "#ffd700" if confidence > 50 else "#ff0000"
                st.markdown(f"**Confidence:** <span style='color:{confidence_color};'>{confidence}%</span>", unsafe_allow_html=True)
            
            # Display remediation steps
            st.markdown("### Recommended Remediation")
            
            remediation_steps = triage_result.get('remediation_steps', ['No steps provided'])
            for i, step in enumerate(remediation_steps):
                st.markdown(f"**{i+1}.** {step}")
            
            # Display reasoning
            st.markdown("### Analysis Reasoning")
            st.info(triage_result.get('reasoning', 'No reasoning provided'))
            
            # Option to re-triage
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Re-triage Vulnerability"):
                    if vuln_id in st.session_state.triage_decisions:
                        del st.session_state.triage_decisions[vuln_id]
                    st.rerun()
            
            with col2:
                if st.button("Return to Dashboard"):
                    st.session_state.selected_vuln_for_triage = None
                    navigate_to("Dashboard")
        else:
            # Perform new triage
            triage_btn = st.button("Start Auto-Triage Analysis")
            
            if triage_btn:
                triaging_agent = create_triaging_agent()
                
                if triaging_agent:
                    with st.spinner("AI agent performing triage analysis..."):
                        triage_result = triage_vulnerability(triaging_agent, selected_vuln)
                        
                        # Store triage results
                        st.session_state.triage_decisions[vuln_id] = triage_result
                        
                        st.success(f"Triage for {selected_vuln.get('Name', 'this vulnerability')} recorded successfully!")
                        st.balloons()
                        st.rerun()  # Refresh to show results
                else:
                    st.error("Could not create triaging agent. Check your AI model settings.")
            
            # Option to select a different vulnerability
            if st.button("Select Different Vulnerability"):
                st.session_state.selected_vuln_for_triage = None
                st.rerun()
    else:
        # No vulnerability selected yet
        st.info("No vulnerability selected for triage.")

def about_page():
    """About page implementation."""
    
    
    st.markdown("""
    ### Overview
    
    This application scans GitHub repositories for security vulnerabilities using both the GitHub API
    and AI-powered code analysis. It helps identify potential security issues in your code and dependencies.
    
    ### Features
    
    - **Repository Scanning**: Scan individual or multiple GitHub repositories for vulnerabilities
    - **Vulnerability Analysis**: AI-powered detection and categorization of security issues
    - **Automated Triage**: Auto-triage vulnerabilities to determine if they are true positives
    - **Visualization**: Interactive charts and visualizations of security findings
    - **Multi-Model Support**: Use either OpenAI or Google Gemini models for analysis
    
    ### Getting Started
    
    1. Configure your API keys in the Settings page
    2. Select repositories to scan in the Vulnerability Scanner page
    3. View and analyze results in the Dashboard
    4. Perform detailed triage in the Auto-Triage Console
    
    ### Technologies
    
    This application is built with:
    
    - Streamlit for the user interface
    - GitHub API for repository access
    - OpenAI/Google Gemini for AI analysis
    - Pandas and Plotly for data handling and visualization
    
    ### Version
    
    Version 1.0.0
    """)

# Main app
def main():
    # Sidebar with navigation
    with st.sidebar:
        st.title("GitHub Security Scanner")
        
        # Navigation
        pages = {
            "Settings": "⚙️ Settings",
            "Vulnerability Scanner": "🔍 Vulnerability Scanner", 
            "Dashboard": "📊 Dashboard",
            "Auto-Triage Console": "🔬 Auto-Triage Console",
            "About": "ℹ️ About"
        }
        
        # Use radio buttons for cleaner navigation
        selected_page = st.radio("Navigation", list(pages.values()))
        
        # Map the display name back to the key
        for key, value in pages.items():
            if value == selected_page:
                st.session_state.active_page = key
                break
        
        st.markdown("---")
        st.markdown("### Quick Status")
        
        # Show quick status info
        if st.session_state.categorized_vulnerabilities:
            vuln_count = len(st.session_state.categorized_vulnerabilities)
            st.success(f"🔍 {vuln_count} vulnerabilities found")
            
            # Show critical/high counts if available
            try:
                df = pd.DataFrame(st.session_state.categorized_vulnerabilities)
                if "Severity" in df.columns:
                    critical = sum(df["Severity"] == "Critical")
                    high = sum(df["Severity"] == "High")
                    st.warning(f"⚠️ {critical} Critical, {high} High")
            except:
                pass
        else:
            st.info("No scans completed yet")
        
        st.markdown("---")
        

    # Display the selected page
    if st.session_state.active_page == "Settings":
        settings_page()
    elif st.session_state.active_page == "Vulnerability Scanner":
        scanner_page()
    elif st.session_state.active_page == "Dashboard":
        dashboard_page()
    elif st.session_state.active_page == "Auto-Triage Console":
        triage_console_page()
    elif st.session_state.active_page == "About":
        about_page()

# Run the app
if __name__ == "__main__":
    # Page configuration
    st.set_page_config(
        page_title="GitHub Security Scanner",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    main()

