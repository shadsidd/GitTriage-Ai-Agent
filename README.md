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
    
    
    ###Requirements
        All dependencies are listed in the requirements.txt file. 
        
        #Install them using pip:
        pip install -r requirements.txt
        
        ##Installation
        
        #Clone this repository:
        git clone https://github.com/shadsidd/GitTriage-Ai-Agent.git
        
        cd GitTriage-Ai-Agent
        
        #Install the required dependencies:
        pip install -r requirements.txt
        
        Set up API keys (instructions in the Settings section of the application)

        #How to Run

        The GitHub Security Scanner is a Streamlit application. 
        To run it:
        Navigate to the project directory:

        cd GitTriage-Ai-Agent
        
        #Run the Streamlit application
        streamlit run GitAiAgent.py
        
        The application will start and automatically open in your default web browser. If it doesn't, you can access it at http://localhost:8501

        #Configuration
        You'll need to configure the following API keys in the Settings section:

        GitHub API Token: A personal access token with repo and security_events permissions
        OpenAI API Key: If you want to use OpenAI models for analysis
        Google Gemini API Key: If you want to use Google's Gemini models for analysis

    
    ### Technologies
    
    This application is built with:
    
    - Streamlit for the user interface
    - GitHub API for repository access
    - OpenAI/Google Gemini for AI analysis
    - Pandas and Plotly for data handling and visualization

