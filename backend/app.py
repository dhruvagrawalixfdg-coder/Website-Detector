#!/usr/bin/env python3
"""
AI-Powered Phishing Website Detection System
Comprehensive scanner with URL, Content, Behavioral, and AI analysis
FIXED: Added proper None handling for domain_age_days
"""

import re
import json
import whois
import socket
import requests
import numpy as np
from urllib.parse import urlparse
from datetime import datetime, timedelta
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from bs4 import BeautifulSoup
import ssl
import warnings
warnings.filterwarnings('ignore')

class PhishingScanner:
    def __init__(self, use_llm=False, llm_api_key=None):
        """
        Initialize the phishing scanner
        
        Args:
            use_llm: Whether to use LLM for advanced analysis
            llm_api_key: API key for LLM service (e.g., OpenAI, Gemini)
        """
        self.use_llm = use_llm
        self.llm_api_key = llm_api_key
        self.results = {
            'url_analysis': {},
            'content_analysis': {},
            'behavioral_analysis': {},
            'ai_analysis': {},
            'risk_score': 0,
            'verdict': 'Unknown'
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = {'.tk', '.xyz', '.ml', '.ga', '.cf', '.top', '.club', '.online'}
        
        # Social engineering keywords
        self.social_engineering_keywords = [
            'verify', 'confirm', 'update', 'validate', 'authenticate', 'suspended',
            'deactivated', 'unusual activity', 'security alert', 'free gift',
            'prize', 'lottery', 'inheritance', 'crypto', 'wallet', 'bitcoin',
            'login required', 'account warning', 'limited time', 'exclusive offer'
        ]
        
        # Credential-related patterns
        self.credential_patterns = [
            r'password', r'passwd', r'pwd', r'username', r'userid', r'login',
            r'signin', r'sign-in', r'log-in', r'email', r'phone', r'ssn',
            r'cvv', r'cvc', r'card number', r'credit card'
        ]
        
        # Brand patterns for typosquatting
        self.brands = [
            'google', 'facebook', 'microsoft', 'apple', 'amazon', 'paypal',
            'netflix', 'twitter', 'instagram', 'linkedin', 'bank', 'axis',
            'hdfc', 'sbi', 'icici', 'flipkart', 'amazon'
        ]
        
        # Train a simple ML model for phishing detection
        self._train_ml_model()
        
    def _train_ml_model(self):
        """Train a simple Naive Bayes model for additional detection layer"""
        # Sample training data (URLs and their labels)
        # 0 = benign, 1 = phishing
        sample_urls = [
            'https://google.com', 'https://facebook.com', 'https://amazon.com',
            'https://paypal.com', 'https://microsoft.com', 'https://apple.com',
            'https://go0gle.com', 'https://faceb00k.com', 'https://amaz0n.com',
            'https://pay-pal.com', 'https://secure-login.com', 'https://verify-account.net',
            'https://banking-update.xyz', 'https://account-suspended.org',
            'https://free-crypto-wallet.ml', 'https://netflix-verify.tk'
        ]
        labels = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        
        self.vectorizer = CountVectorizer(analyzer='char', ngram_range=(3, 5))
        X = self.vectorizer.fit_transform(sample_urls)
        self.ml_model = MultinomialNB()
        self.ml_model.fit(X, labels)
    
    def scan(self, url):
        """
        Main scanning function - runs all analysis phases
        
        Args:
            url: The URL to scan
            
        Returns:
            dict: Complete analysis results
        """
        print(f"\n🔍 Scanning URL: {url}")
        print("=" * 60)
        
        # Phase 1: URL & Lexical Analysis
        print("\n📌 PHASE 1: URL & Lexical Analysis")
        self._analyze_url(url)
        
        # Phase 2: Content & Heuristic Analysis
        print("\n📌 PHASE 2: Content & Heuristic Analysis")
        self._analyze_content(url)
        
        # Phase 3: Deep Behavioral & Infrastructure Analysis
        print("\n📌 PHASE 3: Deep Behavioral & Infrastructure Analysis")
        self._analyze_behavior(url)
        
        # Phase 4: AI/ML & Multimodal Reasoning
        print("\n📌 PHASE 4: AI/ML & Multimodal Reasoning")
        self._perform_ai_analysis()
        
        # Calculate final risk score
        self._calculate_risk_score()
        
        # Display results
        self._display_results()
        
        return self.results
    
    # ============ PHASE 1: URL & Lexical Analysis ============
    def _analyze_url(self, url):
        """Perform URL structure, domain, and lexical analysis"""
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        
        analysis = {
            'url': url,
            'domain': domain,
            'path': path,
            'has_query_params': bool(query),
            'length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_slashes': url.count('/'),
            'has_ip': False,
            'suspicious_tld': False,
            'typosquatting': False,
            'punycode': False,
            'suspicious_subdomains': False,
            'url_shortened': False,
            'findings': []
        }
        
        # Check for IP address in URL
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, domain):
            analysis['has_ip'] = True
            analysis['findings'].append('IP address used instead of domain name')
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if url.endswith(tld):
                analysis['suspicious_tld'] = True
                analysis['findings'].append(f'Suspicious TLD detected: {tld}')
                break
        
        # Check for typosquatting - IMPROVED
        domain_clean = re.sub(r'[^a-zA-Z0-9]', '', domain).lower()
        for brand in self.brands:
            if brand in domain_clean:
                # Check if it's actually the legitimate domain
                if domain_clean == brand:
                    # It's the exact brand name, likely legitimate
                    continue
                # Check for common typosquatting patterns
                if not domain_clean.endswith(brand) and domain_clean != brand:
                    # Levenshtein distance approximation
                    if self._levenshtein_ratio(brand, domain_clean) < 0.8:
                        analysis['typosquatting'] = True
                        analysis['findings'].append(f'Possible typosquatting targeting {brand}')
                        break
        
        # Check for Punycode/homograph attacks
        if 'xn--' in domain:
            analysis['punycode'] = True
            analysis['findings'].append('Punycode detected - possible homograph attack')
        
        # Check for suspicious subdomains (too many levels)
        if len(domain.split('.')) > 3:
            analysis['suspicious_subdomains'] = True
            analysis['findings'].append('Excessive subdomain levels detected')
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        for shortener in shorteners:
            if shortener in domain:
                analysis['url_shortened'] = True
                analysis['findings'].append(f'URL shortened using {shortener}')
                break
        
        # Lexical features
        analysis['entropy'] = self._calculate_entropy(url)
        if analysis['entropy'] > 4.5:
            analysis['findings'].append('High entropy in URL (random-looking string)')
        
        self.results['url_analysis'] = analysis
        print(f"  ✓ Domain: {domain}")
        print(f"  ✓ Suspicious indicators: {len(analysis['findings'])}")
        for finding in analysis['findings']:
            print(f"    - {finding}")
    
    def _levenshtein_ratio(self, s1, s2):
        """Calculate similarity ratio between two strings"""
        if len(s1) == 0 or len(s2) == 0:
            return 0
        # Simple approximation for demo
        max_len = max(len(s1), len(s2))
        matches = sum(1 for a, b in zip(s1, s2) if a == b)
        return matches / max_len
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        entropy = -sum([p * np.log2(p) for p in prob if p > 0])
        return entropy
    
    # ============ PHASE 2: Content & Heuristic Analysis ============
    def _analyze_content(self, url):
        """Analyze HTML content, forms, scripts, and visible text"""
        analysis = {
            'has_forms': False,
            'has_credential_fields': False,
            'has_social_engineering': False,
            'has_login_form': False,
            'has_hidden_fields': False,
            'has_obfuscated_js': False,
            'has_external_js': False,
            'brand_mentions': [],
            'findings': [],
            'form_action': None,
            'credential_fields': []
        }
        
        try:
            # Add headers to avoid blocking
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Fetch the page content
            response = requests.get(url, timeout=10, verify=False, headers=headers)
            
            # Only parse if response is HTML
            content_type = response.headers.get('content-type', '')
            if 'text/html' in content_type or response.text.strip().startswith('<'):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for forms
                forms = soup.find_all('form')
                if forms:
                    analysis['has_forms'] = True
                    analysis['findings'].append(f'Found {len(forms)} form(s) on page')
                    
                    for form in forms:
                        # Check form action
                        action = form.get('action', '')
                        if action and 'http' in action and urlparse(action).netloc != urlparse(url).netloc:
                            analysis['form_action'] = action
                            analysis['findings'].append(f'Form submits to external domain: {action}')
                        
                        # Check for hidden fields
                        hidden_fields = form.find_all('input', type='hidden')
                        if hidden_fields:
                            analysis['has_hidden_fields'] = True
                            analysis['findings'].append('Hidden form fields detected (potential data theft)')
                        
                        # Check for credential fields
                        inputs = form.find_all('input')
                        for inp in inputs:
                            input_type = inp.get('type', '').lower()
                            input_name = inp.get('name', '').lower()
                            input_id = inp.get('id', '').lower()
                            
                            for pattern in self.credential_patterns:
                                if pattern in input_name or pattern in input_id:
                                    analysis['has_credential_fields'] = True
                                    analysis['credential_fields'].append(f"{input_name or input_id} ({input_type})")
                                    break
                            
                            if input_type in ['password', 'email', 'tel']:
                                analysis['has_credential_fields'] = True
                                analysis['credential_fields'].append(f"{input_name or input_id} ({input_type})")
                
                # Check for social engineering keywords in text
                text = soup.get_text().lower()
                found_keywords = []
                for keyword in self.social_engineering_keywords:
                    if keyword in text:
                        found_keywords.append(keyword)
                
                if found_keywords:
                    analysis['has_social_engineering'] = True
                    analysis['findings'].append(f'Social engineering keywords found: {", ".join(found_keywords[:5])}')
                
                # Check for JavaScript obfuscation
                scripts = soup.find_all('script')
                for script in scripts:
                    script_text = script.string or ''
                    if 'eval(' in script_text or 'atob(' in script_text or 'fromCharCode' in script_text:
                        analysis['has_obfuscated_js'] = True
                        analysis['findings'].append('Obfuscated JavaScript detected')
                        break
                    if 'src' in script.attrs and 'http' in script['src']:
                        analysis['has_external_js'] = True
                
                # Check for brand mentions (potential impersonation)
                for brand in self.brands:
                    if brand in text.lower():
                        analysis['brand_mentions'].append(brand)
                
                if analysis['brand_mentions']:
                    analysis['findings'].append(f'Brand mentions: {", ".join(analysis["brand_mentions"])}')
            else:
                analysis['findings'].append('Non-HTML content or binary file')
                
        except requests.exceptions.SSLError:
            analysis['findings'].append('SSL certificate verification failed')
        except requests.exceptions.ConnectionError:
            analysis['findings'].append('Connection error - site may be down')
        except requests.exceptions.Timeout:
            analysis['findings'].append('Timeout while fetching page')
        except Exception as e:
            analysis['findings'].append(f'Content analysis error: {str(e)}')
        
        self.results['content_analysis'] = analysis
        print(f"  ✓ Forms found: {analysis['has_forms']}")
        print(f"  ✓ Credential fields: {len(analysis['credential_fields'])}")
        print(f"  ✓ Social engineering keywords: {analysis['has_social_engineering']}")
    
    # ============ PHASE 3: Deep Behavioral & Infrastructure ============
    def _analyze_behavior(self, url):
        """Analyze page behavior, reputation, SSL, and technical setup"""
        analysis = {
            'ssl_valid': False,
            'ssl_issuer': None,
            'ssl_expiry': None,
            'domain_age_days': None,  # Default to None
            'domain_registrar': None,
            'has_redirects': False,
            'redirect_count': 0,
            'final_url': None,
            'brand_domain_match': True,
            'page_load_time': None,
            'has_meta_tags': False,
            'has_canonical_url': False,
            'security_headers': {},
            'findings': []
        }
        
        # SSL Certificate Analysis
        try:
            # Parse domain for SSL check
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        analysis['ssl_valid'] = True
                        analysis['ssl_issuer'] = cert.get('issuer', [])
                        not_after = cert.get('notAfter')
                        if not_after:
                            try:
                                analysis['ssl_expiry'] = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                # Check if certificate is expired
                                if analysis['ssl_expiry'] < datetime.now():
                                    analysis['findings'].append('SSL certificate expired')
                            except ValueError:
                                analysis['findings'].append('Invalid SSL certificate date format')
                        
                        # Check for wildcard or self-signed
                        subject = dict(x[0] for x in cert.get('subject', []))
                        if 'commonName' in subject and '*.' in subject['commonName']:
                            analysis['findings'].append('Wildcard SSL certificate')
        except socket.gaierror:
            analysis['findings'].append('DNS resolution failed - invalid domain')
        except socket.timeout:
            analysis['findings'].append('SSL connection timeout')
        except ConnectionRefusedError:
            analysis['findings'].append('SSL connection refused - port 443 may be closed')
        except Exception as e:
            analysis['findings'].append(f'SSL check failed: {str(e)}')
        
        # WHOIS/Domain Reputation
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                if creation_date:
                    domain_age = (datetime.now() - creation_date).days
                    analysis['domain_age_days'] = domain_age
                    
                    if domain_age < 30:
                        analysis['findings'].append(f'Very young domain: {domain_age} days old')
                    elif domain_age < 90:
                        analysis['findings'].append(f'Relatively new domain: {domain_age} days old')
                
                analysis['domain_registrar'] = w.registrar if w.registrar else 'Unknown'
                
        except whois.parser.PywhoisError:
            analysis['findings'].append('WHOIS lookup failed - domain may not exist')
        except socket.gaierror:
            analysis['findings'].append('WHOIS lookup failed - DNS resolution error')
        except Exception as e:
            analysis['findings'].append(f'WHOIS lookup failed: {str(e)}')
        
        # Check for redirects
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True, headers=headers)
            analysis['redirect_count'] = len(response.history)
            if analysis['redirect_count'] > 0:
                analysis['has_redirects'] = True
                analysis['final_url'] = response.url
                analysis['findings'].append(f'Redirects detected: {analysis["redirect_count"]} redirect(s)')
                
                # Check if final URL is different domain
                original_domain = urlparse(url).netloc
                final_domain = urlparse(response.url).netloc
                if original_domain != final_domain:
                    analysis['findings'].append(f'Redirected to different domain: {final_domain}')
        except requests.exceptions.SSLError:
            analysis['findings'].append('SSL error during redirect check')
        except requests.exceptions.ConnectionError:
            analysis['findings'].append('Connection error during redirect check')
        except Exception as e:
            analysis['findings'].append(f'Redirect check failed: {str(e)}')
        
        # Check for brand vs domain mismatch
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check if any brand name appears in the domain
            for brand in self.brands:
                if brand in domain:
                    # Check if it's actually the legitimate domain
                    if domain == f"{brand}.com" or domain == f"www.{brand}.com":
                        analysis['brand_domain_match'] = True
                        break
                    else:
                        analysis['brand_domain_match'] = False
                        analysis['findings'].append(f'Brand {brand} mentioned but domain does not match expected pattern')
                        break
            
            # Additional: Check for data exfiltration endpoints
            if self.results.get('content_analysis', {}).get('form_action'):
                form_action = self.results['content_analysis']['form_action']
                if form_action and 'http' in form_action:
                    parsed_action = urlparse(form_action)
                    if parsed_action.netloc and parsed_action.netloc != parsed.netloc:
                        analysis['findings'].append(f'Data exfiltration risk: form submits to {parsed_action.netloc}')
        except Exception as e:
            analysis['findings'].append(f'Brand check failed: {str(e)}')
        
        # Store security headers if available
        try:
            response = requests.head(url, timeout=5, verify=False, headers={'User-Agent': 'Mozilla/5.0'})
            for header in ['Strict-Transport-Security', 'X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy']:
                if header in response.headers:
                    analysis['security_headers'][header] = response.headers[header]
        except:
            pass
        
        self.results['behavioral_analysis'] = analysis
        
        # Display results with safe None handling
        print(f"  ✓ SSL Certificate: {'Valid' if analysis['ssl_valid'] else 'Invalid/Not Found'}")
        
        # Safe display of domain age
        domain_age = analysis.get('domain_age_days')
        if domain_age is not None:
            print(f"  ✓ Domain age: {domain_age} days")
        else:
            print(f"  ✓ Domain age: Unknown")
            
        print(f"  ✓ Redirects: {analysis['redirect_count']}")
        if analysis['brand_domain_match'] == False:
            print(f"  ⚠️  Brand-domain mismatch detected!")
    
    # ============ PHASE 4: AI/ML & Multimodal Reasoning ============
    def _perform_ai_analysis(self):
        """Synthesize all findings using ML and optional LLM"""
        analysis = {
            'ml_prediction': None,
            'ml_confidence': 0,
            'llm_analysis': None,
            'key_indicators': [],
            'reasoning': [],
            'findings': []
        }
        
        # ML Prediction using the trained model
        try:
            url = self.results['url_analysis']['url']
            X_test = self.vectorizer.transform([url])
            prediction = self.ml_model.predict(X_test)[0]
            confidence = self.ml_model.predict_proba(X_test)[0].max()
            
            analysis['ml_prediction'] = 'Phishing' if prediction == 1 else 'Benign'
            analysis['ml_confidence'] = confidence
            analysis['findings'].append(f'ML prediction: {analysis["ml_prediction"]} ({confidence:.2%} confidence)')
        except Exception as e:
            analysis['findings'].append(f'ML prediction failed: {str(e)}')
        
        # Multimodal reasoning - cross-checking consistency
        url_analysis = self.results.get('url_analysis', {})
        content_analysis = self.results.get('content_analysis', {})
        behavioral_analysis = self.results.get('behavioral_analysis', {})
        
        # Build reasoning based on all phases
        risk_factors = []
        
        # URL-based indicators
        if url_analysis.get('has_ip'):
            risk_factors.append('IP address in URL')
        if url_analysis.get('suspicious_tld'):
            risk_factors.append('Suspicious TLD')
        if url_analysis.get('typosquatting'):
            risk_factors.append('Typosquatting detected')
        if url_analysis.get('punycode'):
            risk_factors.append('Punycode homograph attack')
        if url_analysis.get('entropy', 0) > 4.5:
            risk_factors.append('High entropy/random URL')
        
        # Content-based indicators
        if content_analysis.get('has_credential_fields'):
            risk_factors.append('Credential harvesting form present')
        if content_analysis.get('has_social_engineering'):
            risk_factors.append('Social engineering tactics used')
        if content_analysis.get('has_hidden_fields'):
            risk_factors.append('Hidden fields for data theft')
        if content_analysis.get('has_obfuscated_js'):
            risk_factors.append('Obfuscated JavaScript')
        
        # Behavioral indicators - FIXED: Safe None handling
        domain_age = behavioral_analysis.get('domain_age_days')
        if domain_age is not None and domain_age < 30:
            risk_factors.append('Very recent domain registration')
        elif domain_age is not None and domain_age < 90:
            risk_factors.append('Relatively new domain')
            
        if behavioral_analysis.get('has_redirects'):
            risk_factors.append('Redirects to different domain')
        if behavioral_analysis.get('brand_domain_match') == False:
            risk_factors.append('Brand-domain mismatch (impersonation)')
        if not behavioral_analysis.get('ssl_valid'):
            risk_factors.append('Invalid or missing SSL certificate')
        
        analysis['key_indicators'] = risk_factors
        analysis['reasoning'] = risk_factors
        
        # LLM-based analysis (optional)
        if self.use_llm and self.llm_api_key:
            llm_analysis = self._perform_llm_analysis()
            analysis['llm_analysis'] = llm_analysis
            analysis['findings'].extend(llm_analysis.get('findings', []))
        
        # Synthesize final reasoning
        if risk_factors:
            analysis['reasoning'].append(f"Identified {len(risk_factors)} risk indicators")
            for factor in risk_factors[:5]:  # Show top 5
                analysis['reasoning'].append(f"  - {factor}")
        
        self.results['ai_analysis'] = analysis
        print(f"  ✓ ML Prediction: {analysis['ml_prediction']} ({analysis['ml_confidence']:.2%} confidence)")
        print(f"  ✓ Risk indicators found: {len(risk_factors)}")
    
    def _perform_llm_analysis(self):
        """Optional LLM-based analysis for deep reasoning"""
        # This is a placeholder - integrate with Gemini, OpenAI, etc.
        # Example using simulated analysis
        analysis = {
            'findings': [],
            'risk_assessment': 'High',
            'recommendations': []
        }
        
        # Simulate LLM reasoning based on findings
        all_findings = []
        for phase in ['url_analysis', 'content_analysis', 'behavioral_analysis']:
            all_findings.extend(self.results.get(phase, {}).get('findings', []))
        
        if len(all_findings) > 5:
            analysis['risk_assessment'] = 'Critical'
            analysis['recommendations'].append('Immediate block - multiple phishing indicators')
        elif len(all_findings) > 3:
            analysis['risk_assessment'] = 'High'
            analysis['recommendations'].append('Strongly recommended to block')
        elif len(all_findings) > 1:
            analysis['risk_assessment'] = 'Medium'
            analysis['recommendations'].append('Further investigation recommended')
        else:
            analysis['risk_assessment'] = 'Low'
            analysis['recommendations'].append('Appears safe but monitor')
        
        analysis['findings'].append(f"LLM Risk Assessment: {analysis['risk_assessment']}")
        return analysis
    
    # ============ FINAL SCORING & REPORTING ============
    def _calculate_risk_score(self):
        """Calculate final risk score from all analyses"""
        weights = {
            'has_ip': 15,
            'suspicious_tld': 10,
            'typosquatting': 15,
            'punycode': 20,
            'entropy_high': 5,
            'has_credential_fields': 20,
            'has_social_engineering': 15,
            'has_hidden_fields': 10,
            'has_obfuscated_js': 10,
            'domain_age_new': 15,
            'domain_age_recent': 8,
            'has_redirects': 10,
            'brand_mismatch': 20,
            'ssl_invalid': 15,
            'ml_phishing': 25
        }
        
        # Calculate risk score
        risk_score = 0
        
        # URL analysis contributions
        url_analysis = self.results.get('url_analysis', {})
        if url_analysis.get('has_ip'): risk_score += weights['has_ip']
        if url_analysis.get('suspicious_tld'): risk_score += weights['suspicious_tld']
        if url_analysis.get('typosquatting'): risk_score += weights['typosquatting']
        if url_analysis.get('punycode'): risk_score += weights['punycode']
        if url_analysis.get('entropy', 0) > 4.5: risk_score += weights['entropy_high']
        
        # Content analysis contributions
        content_analysis = self.results.get('content_analysis', {})
        if content_analysis.get('has_credential_fields'): risk_score += weights['has_credential_fields']
        if content_analysis.get('has_social_engineering'): risk_score += weights['has_social_engineering']
        if content_analysis.get('has_hidden_fields'): risk_score += weights['has_hidden_fields']
        if content_analysis.get('has_obfuscated_js'): risk_score += weights['has_obfuscated_js']
        
        # Behavioral analysis contributions - FIXED: Safe None handling
        behavioral_analysis = self.results.get('behavioral_analysis', {})
        domain_age = behavioral_analysis.get('domain_age_days')
        if domain_age is not None:
            if domain_age < 30:
                risk_score += weights['domain_age_new']
            elif domain_age < 90:
                risk_score += weights['domain_age_recent']
        
        if behavioral_analysis.get('has_redirects'): risk_score += weights['has_redirects']
        if behavioral_analysis.get('brand_domain_match') == False: risk_score += weights['brand_mismatch']
        if not behavioral_analysis.get('ssl_valid'): risk_score += weights['ssl_invalid']
        
        # ML contribution
        ai_analysis = self.results.get('ai_analysis', {})
        ml_prediction = ai_analysis.get('ml_prediction')
        if ml_prediction == 'Phishing':
            confidence = ai_analysis.get('ml_confidence', 0)
            risk_score += weights['ml_phishing'] * confidence
        
        # Normalize to 0-100
        max_possible = sum(weights.values())
        normalized_score = min(100, (risk_score / max_possible) * 100)
        
        self.results['risk_score'] = round(normalized_score, 2)
        
        # Determine verdict
        if normalized_score >= 70:
            self.results['verdict'] = '🚨 PHISHING - BLOCK IMMEDIATELY'
        elif normalized_score >= 40:
            self.results['verdict'] = '⚠️ SUSPICIOUS - INVESTIGATE FURTHER'
        elif normalized_score >= 15:
            self.results['verdict'] = 'ℹ️ CAUTION - MINOR CONCERNS'
        else:
            self.results['verdict'] = '✅ SAFE - LIKELY LEGITIMATE'
    
    def _display_results(self):
        """Display comprehensive scan results"""
        print("\n" + "=" * 60)
        print("📊 FINAL SCAN RESULTS")
        print("=" * 60)
        
        print(f"\n📈 Risk Score: {self.results['risk_score']}/100")
        print(f"🎯 Verdict: {self.results['verdict']}")
        
        print("\n📋 Key Findings Summary:")
        
        # Summary of findings by phase
        phases = {
            'URL Analysis': self.results.get('url_analysis', {}).get('findings', []),
            'Content Analysis': self.results.get('content_analysis', {}).get('findings', []),
            'Behavioral Analysis': self.results.get('behavioral_analysis', {}).get('findings', []),
            'AI/ML Analysis': self.results.get('ai_analysis', {}).get('findings', [])
        }
        
        for phase, findings in phases.items():
            if findings:
                print(f"\n  {phase}:")
                for finding in findings[:3]:  # Show top 3 findings per phase
                    print(f"    • {finding}")
                if len(findings) > 3:
                    print(f"    • ... and {len(findings) - 3} more")
        
        # ML specific result
        ml_result = self.results.get('ai_analysis', {}).get('ml_prediction')
        if ml_result:
            print(f"\n🤖 ML Detection: {ml_result}")
            print(f"   Confidence: {self.results.get('ai_analysis', {}).get('ml_confidence', 0):.2%}")
        
        # Security recommendations
        print("\n🔒 Recommendations:")
        if self.results['risk_score'] >= 70:
            print("  • BLOCK this URL immediately")
            print("  • Report to security team")
            print("  • Update firewall/blocklist")
        elif self.results['risk_score'] >= 40:
            print("  • Investigate before access")
            print("  • Monitor for suspicious activity")
            print("  • Consider sandbox testing")
        else:
            print("  • No immediate action required")
            print("  • Continue monitoring")
        
        print("\n" + "=" * 60)

# ================== MAIN EXECUTION ==================

def main():
    """Run the scanner with example URLs"""
    scanner = PhishingScanner(use_llm=False)
    
    # Test with different URLs
    test_urls = [
        'https://www.google.com',
        'https://secure-login-verify.ml',
        'https://faceb00k.com',
        'https://paypal-secure-account.tk',
        # 'https://xn--googl-5wa.com',  # Uncomment to test Punycode
        # 'https://sites.google.com/phishing-test'  # Benign service abused
    ]
    
    for url in test_urls:
        try:
            results = scanner.scan(url)
            print("\n" + "=" * 60)
            print("Detailed JSON Results (summary):")
            
            # Print a clean summary instead of full JSON
            summary = {
                'url': url,
                'risk_score': results['risk_score'],
                'verdict': results['verdict'],
                'ml_prediction': results.get('ai_analysis', {}).get('ml_prediction'),
                'findings_count': len(results.get('url_analysis', {}).get('findings', [])) + 
                                 len(results.get('content_analysis', {}).get('findings', [])) +
                                 len(results.get('behavioral_analysis', {}).get('findings', []))
            }
            print(json.dumps(summary, indent=2))
            
            # Let user continue
            input("\nPress Enter to scan next URL...")
            
        except Exception as e:
            print(f"❌ Error scanning {url}: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()