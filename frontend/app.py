import streamlit as st
import requests
import json
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="AI Phishing Link Analyzer",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .sub-header {
        text-align: center;
        color: #666;
        margin-bottom: 2rem;
    }
    .safe-box {
        background-color: #d4edda;
        border-left: 5px solid #28a745;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .danger-box {
        background-color: #f8d7da;
        border-left: 5px solid #dc3545;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .warning-box {
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    .info-box {
        background-color: #d1ecf1;
        border-left: 5px solid #17a2b8;
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 5px;
    }
    </style>
""", unsafe_allow_html=True)

# API endpoint (adjust based on your FastAPI server)
API_URL = "http://localhost:8000"

# Header
st.markdown('<div class="main-header">🛡 AI Phishing Link Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Real-time detection of malicious links and phishing attempts</div>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.header("⚙ Settings")
    
    analysis_mode = st.radio(
        "Analysis Mode",
        ["Quick Scan", "Deep Analysis", "Batch Analysis"]
    )
    
    st.markdown("---")
    
    st.header("📊 Statistics")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Scans", "1,234")
        st.metric("Threats Blocked", "89")
    with col2:
        st.metric("Safe Links", "1,145")
        st.metric("Accuracy", "98.5%")
    
    st.markdown("---")
    
    st.header("ℹ About")
    st.info("This AI-powered tool analyzes URLs and messages to detect phishing attempts, malware, and other security threats in real-time.")

# Main content
tab1, tab2, tab3, tab4 = st.tabs(["🔍 URL Analysis", "📧 Message Analysis", "📁 Batch Upload", "📈 History"])

with tab1:
    st.header("Analyze a URL")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        url_input = st.text_input(
            "Enter URL to analyze",
            placeholder="https://example.com/suspicious-link",
            help="Paste the URL you want to check for phishing or malware"
        )
    
    with col2:
        st.write("")
        st.write("")
        analyze_button = st.button("🔍 Analyze URL", type="primary", use_container_width=True)
    
    if analyze_button and url_input:
        with st.spinner("🔄 Analyzing URL... This may take a few seconds..."):
            try:
                # Make API call to backend
                response = requests.post(
                    f"{API_URL}/analyze/url",
                    json={"url": url_input},
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Display results based on threat level
                    threat_level = result.get("threat_level", "unknown").lower()
                    confidence = result.get("confidence", 0) * 100
                    
                    st.markdown("---")
                    
                    if threat_level == "safe":
                        st.markdown(f"""
                        <div class="safe-box">
                            <h3>✅ Safe Link</h3>
                            <p><strong>Confidence:</strong> {confidence:.1f}%</p>
                            <p>This link appears to be safe and legitimate.</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    elif threat_level == "suspicious":
                        st.markdown(f"""
                        <div class="warning-box">
                            <h3>⚠ Suspicious Link</h3>
                            <p><strong>Confidence:</strong> {confidence:.1f}%</p>
                            <p>This link shows some suspicious characteristics. Proceed with caution.</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    elif threat_level in ["malicious", "phishing", "dangerous"]:
                        st.markdown(f"""
                        <div class="danger-box">
                            <h3>🚨 Malicious Link Detected</h3>
                            <p><strong>Confidence:</strong> {confidence:.1f}%</p>
                            <p>This link is potentially dangerous. Do NOT click or visit this URL.</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Detailed Analysis
                    st.subheader("📋 Detailed Analysis")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Threat Type", result.get("threat_type", "N/A"))
                    
                    with col2:
                        st.metric("Risk Score", f"{result.get('risk_score', 0):.1f}/10")
                    
                    with col3:
                        st.metric("Analysis Time", f"{result.get('analysis_time', 0):.2f}s")
                    
                    # Features detected
                    if "features" in result:
                        st.subheader("🔎 Detected Features")
                        features = result["features"]
                        
                        feature_cols = st.columns(2)
                        
                        with feature_cols[0]:
                            st.markdown("*URL Characteristics:*")
                            st.write(f"• Length: {features.get('url_length', 'N/A')}")
                            st.write(f"• Special Characters: {features.get('special_chars', 'N/A')}")
                            st.write(f"• Suspicious Keywords: {features.get('suspicious_keywords', 'No')}")
                        
                        with feature_cols[1]:
                            st.markdown("*Domain Information:*")
                            st.write(f"• Domain Age: {features.get('domain_age', 'Unknown')}")
                            st.write(f"• SSL Certificate: {features.get('ssl_valid', 'Unknown')}")
                            st.write(f"• Redirects: {features.get('redirects', 0)}")
                    
                    # Explanation
                    if "explanation" in result:
                        st.subheader("💡 Why This Classification?")
                        st.info(result["explanation"])
                    
                    # Recommendations
                    st.subheader("✨ Recommendations")
                    recommendations = result.get("recommendations", [
                        "Always verify the sender before clicking links",
                        "Check for HTTPS and valid SSL certificates",
                        "Hover over links to see the actual destination",
                        "Use a reputable antivirus software"
                    ])
                    
                    for rec in recommendations:
                        st.write(f"• {rec}")
                
                else:
                    st.error(f"❌ Analysis failed: {response.status_code} - {response.text}")
            
            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot connect to the backend server. Make sure the FastAPI server is running on http://localhost:8000")
                st.info("💡 Start the server with: uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload")
            
            except Exception as e:
                st.error(f"❌ An error occurred: {str(e)}")
    
    elif analyze_button:
        st.warning("⚠ Please enter a URL to analyze")

with tab2:
    st.header("Analyze a Message")
    
    message_input = st.text_area(
        "Paste suspicious message or email content",
        height=200,
        placeholder="Paste the email or message content here...",
        help="Include the full message text, including any links or suspicious content"
    )
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        analyze_message_btn = st.button("🔍 Analyze Message", type="primary", use_container_width=True)
    
    with col2:
        extract_links_btn = st.button("🔗 Extract Links", use_container_width=True)
    
    if analyze_message_btn and message_input:
        with st.spinner("🔄 Analyzing message..."):
            try:
                response = requests.post(
                    f"{API_URL}/analyze/message",
                    json={"message": message_input},
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    threat_level = result.get("threat_level", "unknown").lower()
                    confidence = result.get("confidence", 0) * 100
                    
                    st.markdown("---")
                    
                    if threat_level == "safe":
                        st.success(f"✅ Message appears safe (Confidence: {confidence:.1f}%)")
                    elif threat_level == "suspicious":
                        st.warning(f"⚠ Suspicious message detected (Confidence: {confidence:.1f}%)")
                    else:
                        st.error(f"🚨 Phishing attempt detected (Confidence: {confidence:.1f}%)")
                    
                    # Display indicators
                    if "indicators" in result:
                        st.subheader("🚩 Phishing Indicators Found")
                        for indicator in result["indicators"]:
                            st.write(f"• {indicator}")
                    
                    # Display extracted links
                    if "links_found" in result and result["links_found"]:
                        st.subheader("🔗 Links Found in Message")
                        for link in result["links_found"]:
                            st.code(link)
                
                else:
                    st.error(f"❌ Analysis failed: {response.status_code}")
            
            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot connect to backend server")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    elif analyze_message_btn:
        st.warning("⚠ Please enter a message to analyze")

with tab3:
    st.header("Batch URL Analysis")
    
    st.info("📌 Upload a file containing multiple URLs (one per line) for batch analysis")
    
    uploaded_file = st.file_uploader(
        "Choose a file",
        type=['txt', 'csv'],
        help="Upload a text or CSV file with URLs"
    )
    
    if uploaded_file is not None:
        urls = uploaded_file.read().decode('utf-8').strip().split('\n')
        urls = [url.strip() for url in urls if url.strip()]
        
        st.write(f"📊 Found {len(urls)} URLs to analyze")
        
        if st.button("🚀 Start Batch Analysis", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            
            for idx, url in enumerate(urls):
                status_text.text(f"Analyzing {idx + 1}/{len(urls)}: {url[:50]}...")
                
                try:
                    response = requests.post(
                        f"{API_URL}/analyze/url",
                        json={"url": url},
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        results.append({
                            "URL": url,
                            "Threat Level": result.get("threat_level", "Unknown"),
                            "Confidence": f"{result.get('confidence', 0) * 100:.1f}%",
                            "Risk Score": result.get("risk_score", 0)
                        })
                    else:
                        results.append({
                            "URL": url,
                            "Threat Level": "Error",
                            "Confidence": "N/A",
                            "Risk Score": "N/A"
                        })
                
                except Exception as e:
                    results.append({
                        "URL": url,
                        "Threat Level": "Error",
                        "Confidence": "N/A",
                        "Risk Score": str(e)
                    })
                
                progress_bar.progress((idx + 1) / len(urls))
            
            status_text.text("✅ Batch analysis complete!")
            
            # Display results
            st.subheader("📊 Batch Analysis Results")
            st.dataframe(results, use_container_width=True)
            
            # Summary statistics
            safe_count = sum(1 for r in results if r["Threat Level"].lower() == "safe")
            malicious_count = sum(1 for r in results if r["Threat Level"].lower() in ["malicious", "phishing", "dangerous"])
            suspicious_count = sum(1 for r in results if r["Threat Level"].lower() == "suspicious")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("✅ Safe", safe_count)
            col2.metric("⚠ Suspicious", suspicious_count)
            col3.metric("🚨 Malicious", malicious_count)

with tab4:
    st.header("Analysis History")
    
    st.info("🔜 History feature coming soon! Your recent analyses will appear here.")
    
    # Placeholder for history
    st.markdown("---")
    st.subheader("Recent Scans")
    
    # Sample history data
    history_data = [
        {"Time": "2024-10-26 10:30", "URL": "https://example.com", "Result": "Safe", "Confidence": "95%"},
        {"Time": "2024-10-26 10:25", "URL": "https://suspicious-site.xyz", "Result": "Malicious", "Confidence": "87%"},
        {"Time": "2024-10-26 10:20", "URL": "https://another-site.com", "Result": "Suspicious", "Confidence": "72%"},
    ]
    
    st.dataframe(history_data, use_container_width=True)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; padding: 2rem;'>
    <p>🛡 AI Phishing Link Analyzer | Built for Security | Powered by AI</p>
    <p>Stay safe online. Always verify before you click.</p>
</div>
""", unsafe_allow_html=True)