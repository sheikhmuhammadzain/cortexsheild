import streamlit as st
import os
import json
import pandas as pd
from Cortex_Shield_Cybergen import CybergenShield
import logging
import datetime
import time
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("StreamlitApp")

# Function to get base64 encoded image
def get_base64_encoded_image(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

# Page configuration
st.set_page_config(
    page_title="Cybergen Cortex Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Get base64 encoded image path
try:
    cybergen_logo = get_base64_encoded_image("static/cybergen.png")
except Exception as e:
    logger.error(f"Error loading logo: {str(e)}")
    cybergen_logo = None

# Custom CSS with enhanced styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        color: #2c3e50;
        margin-bottom: 15px;
        font-weight: 600;
        text-align: center;
    }
    .sub-header {
        font-size: 1.3rem;
        color: #3498DB;
        margin-bottom: 15px;
        text-align: center;
    }
    .logo-image {
        max-width: 100px;
        margin: 0 auto;
        display: block;
        margin-bottom: 15px;
        background-color: white;
        padding: 8px;
        border-radius: 5px;
    }
    .stButton > button {
        background-color: #3498db;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Create reports directory if it doesn't exist
os.makedirs('reports', exist_ok=True)

def process_report(rag_endpoint):
    """Process the report and show progress"""
    
    progress_text = "Initializing security tests..."
    progress_bar = st.progress(0)
    status_placeholder = st.empty()
    
    try:
        # Update status
        status_placeholder.text("Step 1/5: Setting up test environment...")
        progress_bar.progress(10)
        time.sleep(0.5)  # Simulated delay for better UX
        
        # Initialize CybergenShield
        shield = CybergenShield(rag_endpoint=rag_endpoint)
        
        # Update status
        status_placeholder.text("Step 2/5: Preparing test cases...")
        progress_bar.progress(30)
        time.sleep(0.5)
        
        # Update status
        status_placeholder.text("Step 3/5: Testing your RAG endpoint...")
        progress_bar.progress(50)
        
        # Run the test
        report_data = shield.test_model()
        
        # Update status
        status_placeholder.text("Step 4/5: Analyzing results...")
        progress_bar.progress(80)
        time.sleep(0.5)
        
        # Update status
        status_placeholder.text("Step 5/5: Generating report...")
        progress_bar.progress(90)
        time.sleep(0.5)
        
        # Complete
        progress_bar.progress(100)
        status_placeholder.text("Report generation complete!")
        
        # Return the report data
        return report_data
        
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        progress_bar.progress(100)
        status_placeholder.text(f"Error: {str(e)}")
        return None

def display_report(report_data):
    """Display the generated report in a nicely formatted way"""
    
    # Logo and Header
    if cybergen_logo:
        st.markdown(f'<img src="data:image/png;base64,{cybergen_logo}" class="logo-image">', unsafe_allow_html=True)
    
    # Title
    st.title("Cybergen Cortex Shield Report")
    st.caption("Security Analysis for RAG Systems")
    
    # Report metadata
    st.info(f"""
    **RAG Endpoint:** {report_data.get('endpoint', 'Unknown')}  
    **Generated on:** {report_data.get('timestamp', datetime.datetime.now().isoformat())}  
    **Tests Performed:** {report_data.get('performance_metrics', {}).get('total_tests', 0)}
    """)
    
    # Vulnerabilities
    st.subheader("Security Vulnerability Analysis")
    
    vulnerabilities = report_data.get('vulnerabilities', [])
    problematic_count = sum(1 for v in vulnerabilities if v.get('problematic', False))
    error_count = sum(1 for v in vulnerabilities if v.get('problematic') is None)
    
    if error_count > 0:
        st.warning(f"⚠️ Connection Issues Detected: We encountered {error_count} connection errors while testing your RAG system.")
    elif problematic_count > 0:
        st.error(f"⚠️ Security Vulnerabilities Detected: We identified {problematic_count} potential security vulnerabilities in your RAG system's responses.")
    else:
        st.success("✅ No Critical Vulnerabilities: Your RAG system appears to handle the security test cases appropriately.")
    
    # Display each vulnerability test
    for i, vuln in enumerate(vulnerabilities):
        with st.expander(f"Test {i+1}: {vuln.get('prompt', 'Unknown prompt')}"):
            st.markdown(f"**Prompt:** {vuln.get('prompt', 'Unknown prompt')}")
            st.markdown(f"**Response:** {vuln.get('response', 'No response')}")
            
            if vuln.get('problematic') is None:
                st.warning("⚠️ Connection Error")
                st.markdown("Could not assess security - connection to the RAG endpoint failed.")
            elif vuln.get('problematic', False):
                st.error("⚠️ Potentially unsafe response")
                st.markdown("The response does not contain sufficient safeguards or clear refusals for this potentially harmful query.")
            else:
                st.success("✅ Safe response")
                st.markdown("The response appropriately refuses or redirects this potentially harmful query.")
    
    # Recommendations
    st.subheader("Security Recommendations")
    
    recommendations = report_data.get('recommendations', [])
    
    for rec in recommendations:
        st.markdown(f"- {rec}")
    
    # Download buttons
    st.subheader("Export Report")
    st.caption("Download the report in your preferred format:")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Download JSON
        json_data = json.dumps(report_data, indent=2)
        st.download_button(
            label="Download Report Data (JSON)",
            data=json_data,
            file_name="cybergen_report.json",
            mime="application/json"
        )
    
    with col2:
        # Download HTML
        if os.path.exists("GRIT_KB_scan_results.html"):
            with open("GRIT_KB_scan_results.html", "r") as f:
                html_content = f.read()
            
            st.download_button(
                label="Download HTML Report",
                data=html_content,
                file_name="cybergen_report.html",
                mime="text/html"
            )
    
    # Footer
    st.caption("Cybergen Cortex Shield 2025")

def main():
    # Sidebar with logo
    if cybergen_logo:
        st.sidebar.markdown(f'<img src="data:image/png;base64,{cybergen_logo}" class="logo-image">', unsafe_allow_html=True)
    
    st.sidebar.title("Cybergen Cortex Shield")
    st.sidebar.caption("RAG Security Analysis")
    
    st.sidebar.divider()
    st.sidebar.subheader("About")
    st.sidebar.info("Analyzes RAG systems for potential security vulnerabilities and provides actionable recommendations.")
    
    st.sidebar.subheader("Features")
    st.sidebar.info("""
    - Security testing
    - Analysis
    - Reporting
    - Recommendations
    """)
    
    # Main content
    if "report_data" not in st.session_state:
        # Landing page
        if cybergen_logo:
            st.markdown(f'<img src="data:image/png;base64,{cybergen_logo}" class="logo-image">', unsafe_allow_html=True)
        
        st.title("Cybergen Cortex Shield")
        st.caption("RAG Security Testing Platform")
        
        st.info("Test your Retrieval Augmented Generation (RAG) systems for security vulnerabilities and get actionable recommendations to improve your security posture.")
        
        # Input form with styling
        with st.form("endpoint_form"):
            st.subheader("Enter Your RAG Endpoint")
            
            rag_endpoint = st.text_input(
                "RAG API Endpoint URL",
                value="http://10.229.222.15:8000/chatbot"
            )
            
            submit_button = st.form_submit_button("Run Security Analysis")
            
            if submit_button and rag_endpoint:
                # Process the report
                with st.spinner("Processing your request..."):
                    report_data = process_report(rag_endpoint)
                    
                    if report_data:
                        # Store report data in session state
                        st.session_state.report_data = report_data
                        # Rerun to display the report
                        st.rerun()
        
        # Simple how it works section
        st.subheader("How It Works")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.info("**1. Test**\n\nWe test your RAG system with various security prompts.")
        
        with col2:
            st.info("**2. Analyze**\n\nWe analyze responses for potential security issues.")
            
        with col3:
            st.info("**3. Report**\n\nWe provide findings and actionable recommendations.")
    else:
        # Display report page
        display_report(st.session_state.report_data)
        
        # Button to start a new scan
        if st.button("Run Another Scan"):
            del st.session_state.report_data
            st.rerun()

if __name__ == "__main__":
    main()
