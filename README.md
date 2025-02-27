# GitTriage-AI-Agent

An intelligent GitHub security assistant that identifies real vulnerabilities and eliminates false positives through AI-powered triage.


### Overview
    
    This application scans GitHub repositories for security vulnerabilities using both the GitHub API
    and AI Agents would do code analysis. It helps identify actual security issues in your code and dependencies and weed out false positve.
    
    ### Features
    
    - Ai Agent 1: Repository Scanning**: Scan individual or multiple GitHub repositories for vulnerabilities
    - Ai Agent 2: Vulnerability Analysis**: AI-powered detection and categorization of security issues
    - Ai Agent 3: Automated Triage : Auto-triage vulnerabilities to determine if they are true positives
    - Visualization**: Interactive charts and visualizations of security findings
    - Multi-Model Support : Use either OpenAI or Google Gemini models for analysis, can add ollama
    
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