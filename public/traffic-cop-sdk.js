// Enhanced Traffic Cop SDK with VPN/Proxy Detection and Advanced Ad Blocking v2.3
(function(window) {
    'use strict';
    
    class TrafficCopSDK {
        constructor(apiKey, config = {}) {
            this.apiKey = apiKey;
            this.config = {
                endpoint: config.endpoint || 'https://traffic-cop-apii.vercel.app/api/v1/analyze',
                mode: config.mode || 'block',
                blockThreshold: config.blockThreshold || 80,
                challengeThreshold: config.challengeThreshold || 60,
                debug: config.debug || false,
                autoProtect: config.autoProtect !== false,
                realTimeDetection: config.realTimeDetection !== false,
                showBlockMessage: config.showBlockMessage !== false,
                retryAttempts: config.retryAttempts || 3,
                timeout: config.timeout || 10000,
                enableRealTimeTracking: config.enableRealTimeTracking !== false,
                enableVPNDetection: config.enableVPNDetection !== false,
                blockAdsForVPN: config.blockAdsForVPN !== false,
                vpnBlockThreshold: config.vpnBlockThreshold || 65 // Optimized threshold
            };
            
            this.sessionId = this.generateSessionId();
            this.startTime = Date.now();
            this.isBlocked = false;
            this.adsBlocked = false;
            this.vpnDetected = false;
            this.vpnAdBlockingActive = false;
            this.retryCount = 0;
            this.blockedScripts = [];
            
            // Enhanced blocked ad scripts list
            this.blockedAdScripts = [
                'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js',
                'https://securepubads.g.doubleclick.net/tag/js/gpt.js',
                'https://www.googletagservices.com/tag/js/gpt.js',
                'https://googleads.g.doubleclick.net/pagead/js/adsbygoogle.js',
                'https://partner.googleadservices.com/gampad/google_ads.js',
                'https://tpc.googlesyndication.com/sodar/',
                'https://googletagmanager.com/gtag/js'
            ];
            
            // proxycheck.io API key for enhanced detection
            this.proxycheckApiKey = '776969-1r4653-70557d-2317a9';
            
            this.behaviorData = {
                mouseMovements: [],
                clicks: [],
                scrollEvents: [],
                keystrokes: [],
                pageInteractions: 0,
                timeOnPage: 0,
                deviceFingerprint: null
            };
            
            // Real-time visitor tracking data
            this.visitorSession = {
                startTime: Date.now(),
                pageViews: [],
                interactions: 0,
                ipData: null,
                geoData: null,
                vpnProxyData: null
            };
            
            if (this.config.autoProtect) {
                this.init();
            }
        }
        
        init() {
            if (this.config.debug) {
                console.log('🛡️ Traffic Cop SDK v2.3 initialized with enhanced VPN/Proxy ad blocking', this.config);
            }
            
            // Setup preemptive ad blocking monitoring
            this.setupPreemptiveAdBlocking();
            
            // Initialize real-time visitor tracking first
            if (this.config.enableRealTimeTracking) {
                this.initRealTimeTracking();
            }
            
            // Start comprehensive behavior tracking
            this.setupBehaviorTracking();
            
            // Generate device fingerprint
            this.generateDeviceFingerprint();
            
            // Initial analysis after page loads
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', () => {
                    setTimeout(() => this.analyzeCurrentVisitor(), 2000);
                });
            } else {
                setTimeout(() => this.analyzeCurrentVisitor(), 2000);
            }
            
            // Set up real-time monitoring
            if (this.config.realTimeDetection) {
                this.setupRealTimeMonitoring();
            }
        }
        
        // Enhanced preemptive ad blocking setup
        setupPreemptiveAdBlocking() {
            // Override document.createElement immediately
            this.interceptScriptCreation();
            
            // Override DOM manipulation methods
            this.interceptDOMManipulation();
            
            // Setup MutationObserver for dynamic content
            this.setupDynamicScriptMonitoring();
            
            // Block existing scripts if VPN is already detected
            if (this.vpnAdBlockingActive) {
                this.scanAndBlockExistingScripts();
            }
        }
        
        // Enhanced script creation interception
        interceptScriptCreation() {
            const originalCreateElement = document.createElement;
            const self = this;
            
            document.createElement = function(tagName) {
                const element = originalCreateElement.call(document, tagName);
                
                if (tagName.toLowerCase() === 'script') {
                    // Create a proxy for the script element
                    return new Proxy(element, {
                        set(target, property, value) {
                            if (property === 'src' && self.vpnAdBlockingActive) {
                                if (self.shouldBlockAdScript(value)) {
                                    console.log('🚫 VPN User: Blocked script creation via createElement:', value);
                                    self.logVPNAdBlock(value, 'createElement_src');
                                    return true; // Prevent setting the src
                                }
                            }
                            target[property] = value;
                            return true;
                        }
                    });
                }
                
                return element;
            };
        }
        
        // Enhanced DOM manipulation interception
        interceptDOMManipulation() {
            const originalAppendChild = Element.prototype.appendChild;
            const originalInsertBefore = Element.prototype.insertBefore;
            const originalReplaceChild = Element.prototype.replaceChild;
            const self = this;
            
            // Override appendChild
            Element.prototype.appendChild = function(child) {
                if (self.vpnAdBlockingActive && child.tagName === 'SCRIPT') {
                    if (child.src && self.shouldBlockAdScript(child.src)) {
                        console.log('🚫 VPN User: Blocked appendChild:', child.src);
                        self.logVPNAdBlock(child.src, 'appendChild');
                        return child; // Return without appending
                    }
                    if (child.innerHTML && self.containsAdCode(child.innerHTML)) {
                        console.log('🚫 VPN User: Blocked inline ad script via appendChild');
                        self.logVPNAdBlock('inline_ad_script', 'appendChild_inline');
                        return child;
                    }
                }
                return originalAppendChild.call(this, child);
            };
            
            // Override insertBefore
            Element.prototype.insertBefore = function(newNode, referenceNode) {
                if (self.vpnAdBlockingActive && newNode.tagName === 'SCRIPT') {
                    if (newNode.src && self.shouldBlockAdScript(newNode.src)) {
                        console.log('🚫 VPN User: Blocked insertBefore:', newNode.src);
                        self.logVPNAdBlock(newNode.src, 'insertBefore');
                        return newNode;
                    }
                    if (newNode.innerHTML && self.containsAdCode(newNode.innerHTML)) {
                        console.log('🚫 VPN User: Blocked inline ad script via insertBefore');
                        self.logVPNAdBlock('inline_ad_script', 'insertBefore_inline');
                        return newNode;
                    }
                }
                return originalInsertBefore.call(this, newNode, referenceNode);
            };
            
            // Override replaceChild
            Element.prototype.replaceChild = function(newChild, oldChild) {
                if (self.vpnAdBlockingActive && newChild.tagName === 'SCRIPT') {
                    if (newChild.src && self.shouldBlockAdScript(newChild.src)) {
                        console.log('🚫 VPN User: Blocked replaceChild:', newChild.src);
                        self.logVPNAdBlock(newChild.src, 'replaceChild');
                        return oldChild;
                    }
                }
                return originalReplaceChild.call(this, newChild, oldChild);
            };
        }
        
        // Enhanced dynamic script monitoring
        setupDynamicScriptMonitoring() {
            const self = this;
            const observer = new MutationObserver((mutations) => {
                if (!self.vpnAdBlockingActive) return;
                
                mutations.forEach((mutation) => {
                    mutation.addedNodes.forEach((node) => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Check if the node itself is a script
                            if (node.tagName === 'SCRIPT') {
                                if (node.src && self.shouldBlockAdScript(node.src)) {
                                    console.log('🚫 VPN User: Blocked dynamic script via MutationObserver:', node.src);
                                    node.remove();
                                    self.logVPNAdBlock(node.src, 'mutation_observer');
                                } else if (node.innerHTML && self.containsAdCode(node.innerHTML)) {
                                    console.log('🚫 VPN User: Blocked inline ad script via MutationObserver');
                                    node.remove();
                                    self.logVPNAdBlock('inline_ad_script', 'mutation_observer_inline');
                                }
                            }
                            
                            // Check for scripts within the added node
                            if (node.querySelectorAll) {
                                const scripts = node.querySelectorAll('script');
                                scripts.forEach(script => {
                                    if (script.src && self.shouldBlockAdScript(script.src)) {
                                        console.log('🚫 VPN User: Blocked nested script:', script.src);
                                        script.remove();
                                        self.logVPNAdBlock(script.src, 'nested_script');
                                    } else if (script.innerHTML && self.containsAdCode(script.innerHTML)) {
                                        console.log('🚫 VPN User: Blocked nested inline ad script');
                                        script.remove();
                                        self.logVPNAdBlock('inline_ad_script', 'nested_inline');
                                    }
                                });
                            }
                        }
                    });
                });
            });
            
            observer.observe(document.documentElement, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['src']
            });
        }
        
        // Check if script contains ad-related code
        containsAdCode(scriptContent) {
            const adKeywords = [
                'adsbygoogle',
                'googletag',
                'doubleclick',
                'googlesyndication',
                'googleadservices',
                'google_ads',
                'gpt.js',
                'pubads'
            ];
            
            const contentLower = scriptContent.toLowerCase();
            return adKeywords.some(keyword => contentLower.includes(keyword));
        }
        
        // Scan and block existing scripts
        scanAndBlockExistingScripts() {
            const scripts = document.querySelectorAll('script[src]');
            scripts.forEach(script => {
                if (this.shouldBlockAdScript(script.src)) {
                    console.log('🚫 VPN User: Removing existing ad script:', script.src);
                    script.remove();
                    this.logVPNAdBlock(script.src, 'existing_script_removal');
                }
            });
            
            // Also check inline scripts
            const inlineScripts = document.querySelectorAll('script:not([src])');
            inlineScripts.forEach(script => {
                if (this.containsAdCode(script.innerHTML)) {
                    console.log('🚫 VPN User: Removing existing inline ad script');
                    script.remove();
                    this.logVPNAdBlock('inline_ad_script', 'existing_inline_removal');
                }
            });
        }
        
        // Enhanced real-time tracking with VPN/Proxy detection
        async initRealTimeTracking() {
            try {
                console.log('🌍 Initializing real-time visitor tracking with VPN/Proxy detection...');
                await this.getVisitorIPAndLocation();
                
                if (this.config.enableVPNDetection) {
                    await this.detectVPNProxy();
                }
                
                this.setupRealTimeVisitorTracking();
                console.log('✅ Real-time visitor tracking active');
            } catch (error) {
                console.warn('⚠️ Real-time tracking initialization failed:', error);
            }
        }
        
        // Enhanced IP and location detection
        async getVisitorIPAndLocation() {
            try {
                // Method 1: Use ipapi.co for comprehensive data
                const ipResponse = await fetch('https://ipapi.co/json/');
                const ipData = await ipResponse.json();
                
                this.visitorSession.ipData = {
                    ip: ipData.ip,
                    city: ipData.city,
                    region: ipData.region,
                    country: ipData.country_name,
                    countryCode: ipData.country_code,
                    latitude: ipData.latitude,
                    longitude: ipData.longitude,
                    timezone: ipData.timezone,
                    isp: ipData.org,
                    postal: ipData.postal,
                    asn: ipData.asn,
                    threat_types: ipData.threat_types || null
                };
                
                if (this.config.debug) {
                    console.log('🌍 Visitor location detected:', this.visitorSession.ipData);
                }
                
                return this.visitorSession.ipData;
                
            } catch (error) {
                if (this.config.debug) {
                    console.warn('⚠️ IP detection failed, using fallback');
                }
                
                // Fallback method
                try {
                    const fallbackResponse = await fetch('https://api.ipify.org?format=json');
                    const fallbackData = await fallbackResponse.json();
                    
                    this.visitorSession.ipData = {
                        ip: fallbackData.ip,
                        city: 'Unknown',
                        region: 'Unknown',
                        country: 'Unknown',
                        countryCode: 'XX',
                        latitude: 0,
                        longitude: 0,
                        timezone: 'Unknown',
                        isp: 'Unknown',
                        postal: 'Unknown',
                        asn: 'Unknown',
                        threat_types: null
                    };
                    
                    return this.visitorSession.ipData;
                } catch (fallbackError) {
                    console.error('❌ All IP detection methods failed');
                    return null;
                }
            }
        }
        
        // Enhanced VPN/Proxy Detection with proxycheck.io
        async detectVPNProxy() {
            if (!this.visitorSession.ipData) {
                console.warn('⚠️ No IP data available for VPN/Proxy detection');
                return;
            }
            
            let vpnScore = 0;
            const vpnSignals = [];
            
            try {
                // Method 1: Use proxycheck.io API (primary - most accurate)
                try {
                    const proxycheckUrl = `https://proxycheck.io/v2/${this.visitorSession.ipData.ip}?key=${this.proxycheckApiKey}&vpn=3&asn=1&risk=2&port=1&seen=1&days=7&tag=traffic-cop-newsparrow`;
                    
                    console.log(`🔍 Checking IP ${this.visitorSession.ipData.ip} with proxycheck.io API...`);
                    
                    const vpnResponse = await fetch(proxycheckUrl);
                    const vpnData = await vpnResponse.json();
                    
                    if (vpnData.status === 'ok' && vpnData[this.visitorSession.ipData.ip]) {
                        const ipData = vpnData[this.visitorSession.ipData.ip];
                        
                        console.log('📊 proxycheck.io API response:', ipData);
                        
                        // Enhanced proxycheck.io analysis
                        if (ipData.proxy === 'yes') {
                            vpnScore += 70;
                            vpnSignals.push('proxycheck_proxy_confirmed');
                            
                            if (ipData.type) {
                                const typeStr = ipData.type.toLowerCase();
                                vpnSignals.push(`proxy_type_${typeStr}`);
                                if (typeStr === 'vpn') {
                                    vpnScore += 25;
                                    vpnSignals.push('proxycheck_vpn_confirmed');
                                }
                            }
                            
                            if (ipData.port) {
                                vpnSignals.push(`proxy_port_${ipData.port}`);
                            }
                        }
                        
                        if (ipData.vpn === 'yes') {
                            vpnScore += 60;
                            vpnSignals.push('proxycheck_vpn_detected');
                        }
                        
                        if (ipData.risk !== undefined) {
                            const riskScore = parseInt(ipData.risk);
                            vpnScore += Math.min(30, riskScore * 0.3);
                            vpnSignals.push(`proxycheck_risk_${riskScore}`);
                            console.log(`🎯 proxycheck.io risk score: ${riskScore}%`);
                        }
                        
                        // Provider analysis
                        if (ipData.provider) {
                            const providerLower = ipData.provider.toLowerCase();
                            const vpnKeywords = ['vpn', 'proxy', 'hosting', 'datacenter'];
                            
                            vpnKeywords.forEach(keyword => {
                                if (providerLower.includes(keyword)) {
                                    vpnScore += 10;
                                    vpnSignals.push(`provider_${keyword}`);
                                }
                            });
                        }
                        
                        // Country adjustment for Indian IPs
                        if (ipData.country === 'IN') {
                            vpnScore = Math.max(0, vpnScore - 15);
                            vpnSignals.push('indian_ip_adjustment');
                        }
                        
                        console.log(`✅ proxycheck.io analysis: Score=${vpnScore}, Signals=[${vpnSignals.join(', ')}]`);
                    }
                } catch (proxycheckError) {
                    console.warn('proxycheck.io API failed, using fallback detection');
                    
                    // Fallback to vpnapi.io
                    try {
                        const vpnResponse = await fetch(`https://vpnapi.io/api/${this.visitorSession.ipData.ip}?key=free`);
                        const vpnData = await vpnResponse.json();
                        
                        if (vpnData.security) {
                            if (vpnData.security.vpn) {
                                vpnScore += 40;
                                vpnSignals.push('VPN detected by fallback API');
                            }
                            if (vpnData.security.proxy) {
                                vpnScore += 35;
                                vpnSignals.push('Proxy detected by fallback API');
                            }
                            if (vpnData.security.tor) {
                                vpnScore += 50;
                                vpnSignals.push('Tor network detected');
                            }
                            if (vpnData.security.relay) {
                                vpnScore += 30;
                                vpnSignals.push('Relay detected');
                            }
                        }
                    } catch (fallbackError) {
                        console.warn('Fallback VPN API also failed, using basic detection');
                    }
                }
                
                // Method 2: ISP analysis (reduced weight since proxycheck.io is primary)
                if (this.visitorSession.ipData.isp) {
                    const vpnKeywords = ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud', 'server', 'virtual', 'vps'];
                    const ispLower = this.visitorSession.ipData.isp.toLowerCase();
                    
                    vpnKeywords.forEach(keyword => {
                        if (ispLower.includes(keyword)) {
                            vpnScore += 8; // Reduced since proxycheck.io is primary
                            vpnSignals.push(`ISP contains VPN keyword: ${keyword}`);
                        }
                    });
                }
                
                // Method 3: Common VPN providers check
                const commonVPNs = [
                    'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'purevpn',
                    'hotspot shield', 'tunnelbear', 'windscribe', 'protonvpn',
                    'mullvad', 'private internet access', 'pia', 'ipvanish',
                    'hidemyass', 'vyprvpn', 'torguard', 'perfectprivacy'
                ];
                
                if (this.visitorSession.ipData.isp) {
                    const ispLower = this.visitorSession.ipData.isp.toLowerCase();
                    commonVPNs.forEach(vpn => {
                        if (ispLower.includes(vpn)) {
                            vpnScore += 45;
                            vpnSignals.push(`Known VPN provider: ${vpn}`);
                        }
                    });
                }
                
                // Method 4: Timezone analysis
                const browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                if (browserTimezone && this.visitorSession.ipData.timezone) {
                    if (browserTimezone !== this.visitorSession.ipData.timezone) {
                        vpnScore += 15; // Reduced weight
                        vpnSignals.push('Timezone mismatch detected');
                    }
                }
                
                // Method 5: Datacenter/hosting ASN analysis
                if (this.visitorSession.ipData.asn) {
                    const datacenterKeywords = ['hosting', 'datacenter', 'cloud', 'server', 'digital ocean', 'amazon', 'google cloud'];
                    const asnLower = this.visitorSession.ipData.asn.toLowerCase();
                    
                    datacenterKeywords.forEach(keyword => {
                        if (asnLower.includes(keyword)) {
                            vpnScore += 12; // Reduced since proxycheck.io is primary
                            vpnSignals.push(`Datacenter ASN detected: ${keyword}`);
                        }
                    });
                }
                
                this.visitorSession.vpnProxyData = {
                    isVPN: vpnScore >= this.config.vpnBlockThreshold,
                    score: vpnScore,
                    signals: vpnSignals,
                    confidence: Math.min(95, vpnScore)
                };
                
                if (this.visitorSession.vpnProxyData.isVPN) {
                    this.vpnDetected = true;
                    
                    if (this.config.debug) {
                        console.log('🔍 VPN/Proxy detected with proxycheck.io:', this.visitorSession.vpnProxyData);
                    }
                    
                    // Activate ad blocking for VPN users
                    if (this.config.blockAdsForVPN) {
                        this.activateVPNAdBlocking();
                    }
                    
                    this.logEvent('vpn_proxy_detected', this.visitorSession.vpnProxyData);
                }
                
            } catch (error) {
                if (this.config.debug) {
                    console.warn('⚠️ VPN detection failed:', error);
                }
            }
        }
        
        // Enhanced VPN ad blocking activation
        activateVPNAdBlocking() {
            this.vpnAdBlockingActive = true;
            this.adsBlocked = true;
            
            if (this.config.debug) {
                console.log('🚫 VPN/Proxy detected: Activating comprehensive ad blocking');
            }
            
            // Scan and block existing scripts
            this.scanAndBlockExistingScripts();
            
            // Block AdSense and GPT initialization
            this.blockAdSenseInitialization();
            this.blockGPTInitialization();
            
            // Hide existing ad containers
            this.hideAdContainers();
            
            // Block network requests to ad domains
            this.blockAdNetworkRequests();
            
            this.logEvent('vpn_ad_blocking_activated', {
                blockedScripts: this.blockedAdScripts,
                timestamp: Date.now(),
                vpnSignals: this.visitorSession.vpnProxyData?.signals || []
            });
            
            // Show notification if configured
            if (this.config.showBlockMessage) {
                this.showVPNAdBlockingMessage();
            }
        }
        
        // Enhanced AdSense blocking
        blockAdSenseInitialization() {
            // Block adsbygoogle array
            if (window.adsbygoogle) {
                window.adsbygoogle.length = 0;
                window.adsbygoogle.push = function() {
                    console.log('🚫 VPN User: Blocked AdSense push');
                    return 0;
                };
            }
            
            // Override adsbygoogle creation
            Object.defineProperty(window, 'adsbygoogle', {
                get: function() {
                    return {
                        push: function() {
                            console.log('🚫 VPN User: Blocked AdSense initialization');
                            return 0;
                        },
                        length: 0
                    };
                },
                set: function() {
                    console.log('🚫 VPN User: Blocked AdSense assignment');
                    return true;
                },
                configurable: false
            });
        }
        
        // Enhanced GPT blocking
        blockGPTInitialization() {
            // Block googletag
            const blockedGPT = {
                cmd: {
                    push: function() {
                        console.log('🚫 VPN User: Blocked GPT cmd.push');
                        return 0;
                    },
                    length: 0
                },
                defineSlot: function() {
                    console.log('🚫 VPN User: Blocked GPT defineSlot');
                    return {
                        addService: function() { return this; },
                        setTargeting: function() { return this; },
                        setCollapseEmptyDiv: function() { return this; }
                    };
                },
                display: function() {
                    console.log('🚫 VPN User: Blocked GPT display');
                    return;
                },
                enableServices: function() {
                    console.log('🚫 VPN User: Blocked GPT enableServices');
                    return;
                },
                pubads: function() {
                    return {
                        enableSingleRequest: function() { return this; },
                        setTargeting: function() { return this; },
                        enableAsyncRendering: function() { return this; }
                    };
                }
            };
            
            if (window.googletag) {
                Object.assign(window.googletag, blockedGPT);
            }
            
            Object.defineProperty(window, 'googletag', {
                get: function() {
                    return blockedGPT;
                },
                set: function() {
                    console.log('🚫 VPN User: Blocked googletag assignment');
                    return true;
                },
                configurable: false
            });
        }
        
        // Block network requests to ad domains
        blockAdNetworkRequests() {
            // Override fetch for ad domains
            const originalFetch = window.fetch;
            window.fetch = function(url, options) {
                if (typeof url === 'string' && this.shouldBlockAdScript && this.shouldBlockAdScript(url)) {
                    console.log('🚫 VPN User: Blocked fetch request to ad domain:', url);
                    return Promise.reject(new Error('Ad request blocked for VPN user'));
                }
                return originalFetch.call(this, url, options);
            }.bind(this);
            
            // Override XMLHttpRequest for ad domains
            const originalXHROpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                if (typeof url === 'string' && this.shouldBlockAdScript && this.shouldBlockAdScript(url)) {
                    console.log('🚫 VPN User: Blocked XHR request to ad domain:', url);
                    return;
                }
                return originalXHROpen.apply(this, arguments);
            }.bind(this);
        }
        
        // Enhanced script blocking check
        shouldBlockAdScript(src) {
            if (!this.vpnAdBlockingActive || !src) return false;
            
            // Check against specific blocked scripts
            if (this.blockedAdScripts.some(blockedScript => src.includes(blockedScript))) {
                return true;
            }
            
            // Check against ad domains
            const adDomains = [
                'googlesyndication.com',
                'doubleclick.net',
                'googletagservices.com',
                'googleadservices.com',
                'google-analytics.com',
                'googletagmanager.com',
                'adsystem.com',
                'adsense.com'
            ];
            
            return adDomains.some(domain => src.includes(domain));
        }
        
        // Enhanced ad container hiding
        hideAdContainers() {
            // Hide Google AdSense containers
            document.querySelectorAll('.adsbygoogle').forEach(ad => {
                ad.style.display = 'none !important';
                ad.style.visibility = 'hidden';
                ad.setAttribute('data-traffic-cop-vpn-blocked', 'true');
            });
            
            // Hide GPT ad slots
            document.querySelectorAll('[id*="google_ads"], [class*="google-ad"], [id*="gpt-"], [class*="gpt-"]').forEach(ad => {
                ad.style.display = 'none !important';
                ad.style.visibility = 'hidden';
                ad.setAttribute('data-traffic-cop-vpn-blocked', 'true');
            });
            
            // Hide common ad containers
            const adSelectors = [
                '[class*="ad-container"]', '[id*="ad-container"]',
                '[class*="advertisement"]', '[id*="advertisement"]',
                '[class*="adsense"]', '[id*="adsense"]',
                '[class*="banner"]', '[id*="banner"]',
                '[class*="sponsor"]', '[id*="sponsor"]',
                '.ad', '#ad', '.ads', '#ads'
            ];
            
            adSelectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(ad => {
                    ad.style.display = 'none !important';
                    ad.style.visibility = 'hidden';
                    ad.setAttribute('data-traffic-cop-vpn-blocked', 'true');
                });
            });
        }
        
        // Show VPN ad blocking message
        showVPNAdBlockingMessage() {
            const message = document.createElement('div');
            message.id = 'traffic-cop-vpn-ad-message';
            message.innerHTML = `
                <div style="position: fixed; top: 20px; right: 20px; background: #ff9800; color: white; 
                           padding: 15px; border-radius: 8px; z-index: 999999; font-family: Arial, sans-serif;
                           box-shadow: 0 4px 12px rgba(0,0,0,0.3); max-width: 350px;">
                    <strong>🛡️ VPN/Proxy Detected</strong><br>
                    <small>Google ad scripts have been blocked to prevent fraud.</small><br>
                    <small>Blocked: ${this.blockedScripts.length} ad scripts</small><br>
                    <small>Confidence: ${this.visitorSession.vpnProxyData?.confidence || 0}%</small>
                    <button onclick="this.parentElement.parentElement.remove()" 
                           style="float: right; background: none; border: none; color: white; cursor: pointer; font-size: 18px;">×</button>
                </div>
            `;
            document.body.appendChild(message);
            
            setTimeout(() => {
                if (message.parentNode) {
                    message.parentNode.removeChild(message);
                }
            }, 10000);
        }
        
        // Enhanced VPN ad blocking logging
        logVPNAdBlock(scriptUrl, method) {
            this.blockedScripts.push({
                url: scriptUrl,
                method: method,
                timestamp: Date.now()
            });
            
            this.logEvent('vpn_ad_script_blocked', {
                scriptUrl: scriptUrl,
                method: method,
                totalBlocked: this.blockedScripts.length,
                vpnConfidence: this.visitorSession.vpnProxyData?.confidence || 0
            });
        }
        
        // [Keep all your existing methods unchanged - setupRealTimeVisitorTracking, sendRealTimeVisitorData, 
        // setupBehaviorTracking, collectVisitorData, handleAnalysisResult, etc.]
        
        // Enhanced visitor data collection with VPN/Proxy data
        setupRealTimeVisitorTracking() {
            // Track page views
            this.trackPageView();
            
            // Send initial visitor data with VPN/Proxy information
            this.sendRealTimeVisitorData('page_load');
            
            // Track page visibility changes
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) {
                    this.sendRealTimeVisitorData('page_focus');
                }
            });
            
            // Send periodic updates
            setInterval(() => {
                this.sendRealTimeVisitorData('periodic_update');
            }, 30000); // Every 30 seconds
        }
        
        // Enhanced real-time visitor data with VPN/Proxy info
        async sendRealTimeVisitorData(trigger) {
            if (!this.visitorSession.ipData) {
                if (this.config.debug) {
                    console.warn('⚠️ No IP data available for real-time tracking');
                }
                return;
            }
            
            const visitorData = {
                sessionId: `visitor_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: new Date().toISOString(),
                trigger: trigger,
                website: window.location.hostname,
                url: window.location.href,
                referrer: document.referrer,
                
                // Real IP and geographic data
                ipAddress: this.visitorSession.ipData.ip,
                location: {
                    city: this.visitorSession.ipData.city,
                    region: this.visitorSession.ipData.region,
                    country: this.visitorSession.ipData.country,
                    countryCode: this.visitorSession.ipData.countryCode,
                    latitude: this.visitorSession.ipData.latitude,
                    longitude: this.visitorSession.ipData.longitude,
                    timezone: this.visitorSession.ipData.timezone,
                    isp: this.visitorSession.ipData.isp,
                    postal: this.visitorSession.ipData.postal,
                    asn: this.visitorSession.ipData.asn
                },
                
                // VPN/Proxy data
                vpnProxy: this.visitorSession.vpnProxyData || null,
                adsBlocked: this.adsBlocked,
                vpnDetected: this.vpnDetected,
                vpnAdBlockingActive: this.vpnAdBlockingActive,
                blockedScriptsCount: this.blockedScripts.length,
                
                // Browser and device data
                userAgent: navigator.userAgent,
                language: navigator.language,
                platform: navigator.platform,
                screenResolution: `${screen.width}x${screen.height}`,
                
                // Session data
                timeOnPage: Math.round((Date.now() - this.visitorSession.startTime) / 1000),
                interactions: this.visitorSession.interactions,
                pageViews: this.visitorSession.pageViews.length
            };
            
            try {
                // Send to Traffic Cop real-time API
                const response = await fetch('https://traffic-cop-apii.vercel.app/api/v1/real-time-visitor', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.apiKey}`
                    },
                    body: JSON.stringify(visitorData)
                });
                
                if (response.ok && this.config.debug) {
                    console.log('📡 Real-time visitor data sent successfully');
                }
                
            } catch (error) {
                if (this.config.debug) {
                    console.warn('⚠️ Failed to send real-time data:', error);
                }
            }
        }
        
        // Enhanced behavior tracking
        setupBehaviorTracking() {
            // Track mouse movements for bot detection
            let lastMouseTime = 0;
            document.addEventListener('mousemove', (event) => {
                const now = Date.now();
                const timeDiff = now - lastMouseTime;
                
                this.behaviorData.mouseMovements.push({
                    x: event.clientX,
                    y: event.clientY,
                    timestamp: now,
                    timeDiff: timeDiff
                });
                
                // Keep only last 50 movements
                if (this.behaviorData.mouseMovements.length > 50) {
                    this.behaviorData.mouseMovements.shift();
                }
                
                lastMouseTime = now;
                
                // Check for bot-like patterns
                this.checkMouseBotPatterns();
            });
            
            // Track clicks for rapid clicking detection
            document.addEventListener('click', (event) => {
                const now = Date.now();
                this.behaviorData.clicks.push({
                    x: event.clientX,
                    y: event.clientY,
                    timestamp: now,
                    target: event.target.tagName
                });
                
                this.behaviorData.pageInteractions++;
                this.visitorSession.interactions++; // Also track for real-time
                
                // Keep only last 20 clicks
                if (this.behaviorData.clicks.length > 20) {
                    this.behaviorData.clicks.shift();
                }
                
                // Check for rapid clicking (bot behavior)
                this.checkRapidClicking();
                
                // Send real-time update on interactions
                if (this.visitorSession.interactions % 5 === 0) {
                    this.sendRealTimeVisitorData('user_interaction');
                }
            });
            
            // Track scroll behavior
            let lastScrollTime = 0;
            document.addEventListener('scroll', () => {
                const now = Date.now();
                this.behaviorData.scrollEvents.push({
                    scrollY: window.scrollY,
                    timestamp: now,
                    timeDiff: now - lastScrollTime
                });
                
                // Keep only last 20 scroll events
                if (this.behaviorData.scrollEvents.length > 20) {
                    this.behaviorData.scrollEvents.shift();
                }
                
                lastScrollTime = now;
            });
            
            // Track keystrokes
            document.addEventListener('keydown', () => {
                this.behaviorData.keystrokes.push({
                    timestamp: Date.now()
                });
                
                // Keep only last 50 keystrokes
                if (this.behaviorData.keystrokes.length > 50) {
                    this.behaviorData.keystrokes.shift();
                }
            });
            
            // Track page visibility changes
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) {
                    this.logEvent('page_hidden');
                } else {
                    this.logEvent('page_visible');
                }
            });
        }
        
        // Enhanced visitor data collection with VPN/Proxy information
        collectVisitorData() {
            const baseData = {
                sessionId: this.sessionId,
                url: window.location.href,
                website: window.location.hostname,
                referrer: document.referrer,
                userAgent: navigator.userAgent,
                screenResolution: `${screen.width}x${screen.height}`,
                viewportSize: `${window.innerWidth}x${window.innerHeight}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                language: navigator.language,
                platform: navigator.platform,
                cookieEnabled: navigator.cookieEnabled,
                timestamp: this.startTime,
                loadTime: Date.now() - this.startTime,
                plugins: navigator.plugins.length,
                jsEnabled: true,
                
                // Enhanced behavior data
                behaviorData: {
                    mouseMovements: this.behaviorData.mouseMovements.length,
                    clicks: this.behaviorData.clicks.length,
                    scrollEvents: this.behaviorData.scrollEvents.length,
                    keystrokes: this.behaviorData.keystrokes.length,
                    pageInteractions: this.behaviorData.pageInteractions,
                    timeOnPage: this.behaviorData.timeOnPage,
                    
                    // Mouse movement analysis
                    mouseVariation: this.calculateMouseVariation(),
                    avgClickSpeed: this.calculateAvgClickSpeed(),
                    scrollPattern: this.analyzeScrollPattern()
                },
                
                // Device fingerprint
                deviceFingerprint: this.behaviorData.deviceFingerprint,
                
                // Enhanced VPN/Proxy detection data
                vpnProxy: this.visitorSession.vpnProxyData || null,
                vpnDetected: this.vpnDetected,
                adsBlocked: this.adsBlocked,
                vpnAdBlockingActive: this.vpnAdBlockingActive,
                blockedScriptsCount: this.blockedScripts.length
            };
            
            // Add real-time visitor data if available
            if (this.visitorSession.ipData) {
                baseData.realTimeData = {
                    ipAddress: this.visitorSession.ipData.ip,
                    location: {
                        city: this.visitorSession.ipData.city,
                        region: this.visitorSession.ipData.region,
                        country: this.visitorSession.ipData.country,
                        countryCode: this.visitorSession.ipData.countryCode,
                        latitude: this.visitorSession.ipData.latitude,
                        longitude: this.visitorSession.ipData.longitude,
                        timezone: this.visitorSession.ipData.timezone,
                        isp: this.visitorSession.ipData.isp,
                        postal: this.visitorSession.ipData.postal,
                        asn: this.visitorSession.ipData.asn
                    },
                    pageViews: this.visitorSession.pageViews.length,
                    sessionInteractions: this.visitorSession.interactions
                };
            }
            
            return baseData;
        }
        
        // Enhanced analysis result handling with VPN/Proxy actions
        handleAnalysisResult(analysis, forcedAnalysis = false) {
            if (this.config.debug) {
                console.log('🔍 Analysis result:', analysis);
            }
            
            // Handle VPN/Proxy specific actions
            if (analysis.blockAds || analysis.vpnProxy?.isVPN) {
                if (!this.vpnAdBlockingActive) {
                    this.activateVPNAdBlocking();
                }
            }
            
            // Execute protection based on risk level and mode
            switch (analysis.action) {
                case 'block':
                    if (this.config.mode === 'block') {
                        this.blockAds();
                        if (this.config.showBlockMessage) {
                            this.showBlockMessage(analysis);
                        }
                        this.logEvent('traffic_blocked', analysis);
                    }
                    break;
                    
                case 'challenge':
                    if (this.config.mode === 'challenge' || this.config.mode === 'block') {
                        this.showChallenge(analysis);
                        this.logEvent('challenge_shown', analysis);
                    }
                    break;
                    
                default:
                    if (!forcedAnalysis && !this.adsBlocked) {
                        this.allowAds();
                        this.logEvent('traffic_allowed', analysis);
                    }
            }
        }
        
        // Enhanced block message with VPN/Proxy information
        showBlockMessage(analysis) {
            const isVPN = analysis.vpnProxy?.isVPN || this.vpnDetected;
            const message = document.createElement('div');
            message.id = 'traffic-cop-block-message';
            message.innerHTML = `
                <div style="position: fixed; top: 20px; right: 20px; background: ${isVPN ? '#ff9800' : '#f44336'}; color: white; 
                           padding: 15px; border-radius: 8px; z-index: 999999; font-family: Arial, sans-serif;
                           box-shadow: 0 4px 12px rgba(0,0,0,0.3); max-width: 300px;">
                    <strong>🛡️ ${isVPN ? 'VPN/Proxy Detected' : 'Bot Traffic Detected'}</strong><br>
                    <small>${isVPN ? 'Google ad scripts blocked to prevent fraud.' : 'Automated traffic blocked to protect this site.'}</small>
                    ${analysis.vpnProxy?.signals ? `<br><small>Signals: ${analysis.vpnProxy.signals.slice(0, 2).join(', ')}</small>` : ''}
                    ${isVPN ? `<br><small>Blocked scripts: ${this.blockedScripts.length}</small>` : ''}
                    <button onclick="this.parentElement.parentElement.remove()" 
                           style="float: right; background: none; border: none; color: white; cursor: pointer; font-size: 18px;">×</button>
                </div>
            `;
            document.body.appendChild(message);
            
            setTimeout(() => {
                if (message.parentNode) {
                    message.parentNode.removeChild(message);
                }
            }, 8000);
        }
        
        // Enhanced stats including VPN/Proxy data
        getStats() {
            try {
                const analytics = JSON.parse(localStorage.getItem('trafficCopAnalytics') || '[]');
                const total = analytics.length;
                const blocked = analytics.filter(a => a.action === 'block').length;
                const vpnDetected = analytics.filter(a => a.vpnProxy?.isVPN).length;
                
                return {
                    totalSessions: total,
                    blockedSessions: blocked,
                    vpnSessions: vpnDetected,
                    blockRate: total > 0 ? Math.round((blocked / total) * 100) : 0,
                    vpnRate: total > 0 ? Math.round((vpnDetected / total) * 100) : 0,
                    isCurrentlyBlocked: this.isBlocked,
                    adsBlocked: this.adsBlocked,
                    vpnDetected: this.vpnDetected,
                    vpnAdBlockingActive: this.vpnAdBlockingActive,
                    blockedScriptsCount: this.blockedScripts.length,
                    blockedScripts: this.blockedScripts
                };
            } catch (e) {
                return {
                    totalSessions: 0,
                    blockedSessions: 0,
                    vpnSessions: 0,
                    blockRate: 0,
                    vpnRate: 0,
                    isCurrentlyBlocked: this.isBlocked,
                    adsBlocked: this.adsBlocked,
                    vpnDetected: this.vpnDetected,
                    vpnAdBlockingActive: this.vpnAdBlockingActive,
                    blockedScriptsCount: this.blockedScripts.length,
                    blockedScripts: this.blockedScripts
                };
            }
        }
        
        // Enhanced VPN data retrieval
        getVPNData() {
            return {
                detected: this.vpnDetected,
                data: this.visitorSession.vpnProxyData,
                adsBlocked: this.adsBlocked,
                adBlockingActive: this.vpnAdBlockingActive,
                blockedScripts: this.blockedScripts,
                blockedScriptsCount: this.blockedScripts.length
            };
        }
        
        // Manual VPN detection method
        async detectVPNManual() {
            await this.detectVPNProxy();
            return this.getVPNData();
        }
        
        // [Keep all your existing methods: checkMouseBotPatterns, checkRapidClicking, 
        // generateDeviceFingerprint, etc. - they remain unchanged]
        
        checkMouseBotPatterns() {
            const movements = this.behaviorData.mouseMovements;
            if (movements.length < 10) return;
            
            // Check for perfectly straight lines (bot behavior)
            const recentMovements = movements.slice(-10);
            let straightLineCount = 0;
            
            for (let i = 2; i < recentMovements.length; i++) {
                const prev = recentMovements[i-2];
                const curr = recentMovements[i-1];
                const next = recentMovements[i];
                
                // Calculate if points are in a straight line
                const slope1 = (curr.y - prev.y) / (curr.x - prev.x);
                const slope2 = (next.y - curr.y) / (next.x - curr.x);
                
                if (Math.abs(slope1 - slope2) < 0.1) {
                    straightLineCount++;
                }
            }
            
            // If too many straight lines, likely a bot
            if (straightLineCount > 6) {
                this.logEvent('bot_mouse_pattern_detected', {
                    straightLineCount,
                    confidence: 85
                });
                this.triggerBotDetection('mouse_pattern');
            }
            
            // Check for no mouse movement variation
            const xVariation = Math.max(...recentMovements.map(m => m.x)) - Math.min(...recentMovements.map(m => m.x));
            const yVariation = Math.max(...recentMovements.map(m => m.y)) - Math.min(...recentMovements.map(m => m.y));
            
            if (xVariation < 5 && yVariation < 5 && recentMovements.length > 5) {
                this.triggerBotDetection('no_mouse_variation');
            }
        }
        
        checkRapidClicking() {
            const clicks = this.behaviorData.clicks;
            if (clicks.length < 5) return;
            
            const recentClicks = clicks.slice(-5);
            const timeDiffs = [];
            
            for (let i = 1; i < recentClicks.length; i++) {
                timeDiffs.push(recentClicks[i].timestamp - recentClicks[i-1].timestamp);
            }
            
            const avgTimeBetweenClicks = timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;
            
            // If clicking faster than humanly possible
            if (avgTimeBetweenClicks < 100) {
                this.logEvent('rapid_clicking_detected', {
                    avgTimeBetweenClicks,
                    confidence: 90
                });
                this.triggerBotDetection('rapid_clicking');
            }
        }
        
        generateDeviceFingerprint() {
            const fingerprint = {
                userAgent: navigator.userAgent,
                language: navigator.language,
                languages: navigator.languages,
                platform: navigator.platform,
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack,
                screenResolution: `${screen.width}x${screen.height}`,
                screenColorDepth: screen.colorDepth,
                timezoneOffset: new Date().getTimezoneOffset(),
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                plugins: Array.from(navigator.plugins).map(p => p.name),
                webdriver: navigator.webdriver,
                hardwareConcurrency: navigator.hardwareConcurrency,
                deviceMemory: navigator.deviceMemory,
                connection: navigator.connection ? {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt
                } : null,
                localStorage: this.checkLocalStorage(),
                sessionStorage: this.checkSessionStorage(),
                indexedDB: this.checkIndexedDB()
            };
            
            this.behaviorData.deviceFingerprint = fingerprint;
            
            // Check for bot indicators in fingerprint
            this.checkDeviceBotIndicators(fingerprint);
        }
        
        checkLocalStorage() {
            try {
                localStorage.setItem('tc_test', 'test');
                localStorage.removeItem('tc_test');
                return true;
            } catch (e) {
                return false;
            }
        }
        
        checkSessionStorage() {
            try {
                sessionStorage.setItem('tc_test', 'test');
                sessionStorage.removeItem('tc_test');
                return true;
            } catch (e) {
                return false;
            }
        }
        
        checkIndexedDB() {
            return 'indexedDB' in window;
        }
        
        checkDeviceBotIndicators(fingerprint) {
            let botScore = 0;
            const indicators = [];
            
            // Check for headless browser indicators
            if (fingerprint.webdriver === true) {
                botScore += 40;
                indicators.push('WebDriver detected');
            }
            
            // Check for unusual plugin count
            if (fingerprint.plugins.length === 0) {
                botScore += 25;
                indicators.push('No plugins detected');
            } else if (fingerprint.plugins.length > 50) {
                botScore += 20;
                indicators.push('Excessive plugins detected');
            }
            
            // Check for bot user agents
            const botKeywords = ['bot', 'crawler', 'spider', 'scraper', 'headless', 'phantom', 'selenium', 'python'];
            const userAgentLower = fingerprint.userAgent.toLowerCase();
            
            botKeywords.forEach(keyword => {
                if (userAgentLower.includes(keyword)) {
                    botScore += 30;
                    indicators.push(`Bot keyword detected: ${keyword}`);
                }
            });
            
            // Check for suspicious screen resolution
            if (fingerprint.screenResolution === '1024x768' || fingerprint.screenResolution === '800x600') {
                botScore += 15;
                indicators.push('Suspicious screen resolution');
            }
            
            // Check for missing features
            if (!fingerprint.deviceMemory && !fingerprint.hardwareConcurrency) {
                botScore += 20;
                indicators.push('Missing hardware information');
            }
            
            // Check for disabled storage
            if (!fingerprint.localStorage || !fingerprint.sessionStorage) {
                botScore += 15;
                indicators.push('Storage disabled');
            }
            
            if (botScore > 50) {
                this.logEvent('device_bot_indicators', {
                    botScore,
                    indicators,
                    confidence: Math.min(95, botScore)
                });
                this.triggerBotDetection('device_fingerprint');
            }
        }
        
        setupRealTimeMonitoring() {
            // Monitor for bot-like behavior every 5 seconds
            setInterval(() => {
                this.performRealTimeAnalysis();
            }, 5000);
            
            // Monitor page interaction patterns
            setInterval(() => {
                this.checkInteractionPatterns();
            }, 10000);
        }
        
        performRealTimeAnalysis() {
            const timeOnPage = Date.now() - this.startTime;
            this.behaviorData.timeOnPage = timeOnPage;
            
            // Check for lack of human interaction
            if (timeOnPage > 30000 && this.behaviorData.pageInteractions === 0) {
                this.triggerBotDetection('no_interaction');
            }
            
            // Check for too much interaction (bot spam)
            if (timeOnPage < 10000 && this.behaviorData.pageInteractions > 50) {
                this.triggerBotDetection('excessive_interaction');
            }
        }
        
        checkInteractionPatterns() {
            // Check scroll behavior
            if (this.behaviorData.scrollEvents.length > 0) {
                const scrollSpeeds = this.behaviorData.scrollEvents.map((event, index) => {
                    if (index === 0) return 0;
                    const prevEvent = this.behaviorData.scrollEvents[index - 1];
                    const distance = Math.abs(event.scrollY - prevEvent.scrollY);
                    const time = event.timeDiff;
                    return time > 0 ? distance / time : 0;
                });
                
                const avgScrollSpeed = scrollSpeeds.reduce((a, b) => a + b, 0) / scrollSpeeds.length;
                
                // If scrolling too fast or too uniform
                if (avgScrollSpeed > 10 || (scrollSpeeds.every(speed => Math.abs(speed - avgScrollSpeed) < 0.1) && scrollSpeeds.length > 5)) {
                    this.triggerBotDetection('suspicious_scroll_pattern');
                }
            }
        }
        
        triggerBotDetection(reason) {
            if (this.isBlocked) return; // Already blocked
            
            this.logEvent('bot_detected', {
                reason,
                timestamp: Date.now(),
                confidence: 85
            });
            
            // Immediately re-analyze with current behavior data
            this.analyzeCurrentVisitor(true);
        }
        
        trackPageView() {
            this.visitorSession.pageViews.push({
                url: window.location.href,
                title: document.title,
                timestamp: Date.now()
            });
            
            this.sendRealTimeVisitorData('page_view');
        }
        
        async analyzeCurrentVisitor(forcedAnalysis = false) {
            try {
                const visitorData = this.collectVisitorData();
                const response = await this.sendAnalysisRequest(visitorData);
                
                if (response.ok) {
                    const analysis = await response.json();
                    this.handleAnalysisResult(analysis, forcedAnalysis);
                    this.storeAnalysis(analysis);
                    
                    // Trigger custom event for publisher
                    this.triggerEvent('trafficCopAnalysis', analysis);
                } else {
                    if (this.config.debug) {
                        console.warn('Traffic Cop analysis failed:', response.status);
                    }
                }
                
            } catch (error) {
                if (this.config.debug) {
                    console.error('Traffic Cop error:', error);
                }
                
                // Retry logic
                if (this.retryCount < this.config.retryAttempts) {
                    this.retryCount++;
                    setTimeout(() => this.analyzeCurrentVisitor(forcedAnalysis), 2000 * this.retryCount);
                }
            }
        }
        
        async sendAnalysisRequest(visitorData) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
            
            try {
                const response = await fetch(this.config.endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.apiKey}`,
                        'Origin': window.location.origin
                    },
                    body: JSON.stringify(visitorData),
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                
                return response;
                
            } catch (error) {
                clearTimeout(timeoutId);
                
                if (this.config.debug) {
                    console.error('Traffic Cop API Error:', error);
                }
                
                // Return fallback response for network errors
                return {
                    ok: false,
                    status: 500,
                    json: async () => ({
                        action: 'allow', // Default to allow on error
                        riskScore: 0,
                        threats: ['Network Error'],
                        sessionId: this.sessionId,
                        confidence: 0
                    })
                };
            }
        }
        
                calculateMouseVariation() {
            const movements = this.behaviorData.mouseMovements;
            if (movements.length < 2) return 0;
            
            const xValues = movements.map(m => m.x);
            const yValues = movements.map(m => m.y);
            
            const xVariation = Math.max(...xValues) - Math.min(...xValues);
            const yVariation = Math.max(...yValues) - Math.min(...yValues);
            
            return xVariation + yVariation;
        }
        
        calculateAvgClickSpeed() {
            const clicks = this.behaviorData.clicks;
            if (clicks.length < 2) return 0;
            
            const timeDiffs = [];
            for (let i = 1; i < clicks.length; i++) {
                timeDiffs.push(clicks[i].timestamp - clicks[i-1].timestamp);
            }
            
            return timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;
        }
        
        analyzeScrollPattern() {
            const scrolls = this.behaviorData.scrollEvents;
            if (scrolls.length < 3) return 'insufficient_data';
            
            const speeds = scrolls.map((scroll, index) => {
                if (index === 0) return 0;
                return scroll.timeDiff > 0 ? Math.abs(scroll.scrollY - scrolls[index-1].scrollY) / scroll.timeDiff : 0;
            });
            
            const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
            
            if (avgSpeed > 10) return 'too_fast';
            if (avgSpeed < 0.1) return 'too_slow';
            
            // Check for uniform scrolling (bot-like)
            const speedVariation = Math.max(...speeds) - Math.min(...speeds);
            if (speedVariation < 0.1 && speeds.length > 5) return 'too_uniform';
            
            return 'normal';
        }
        
        blockAds() {
            this.isBlocked = true;
            
            // Hide Google AdSense ads
            document.querySelectorAll('.adsbygoogle').forEach(ad => {
                ad.style.display = 'none';
                ad.setAttribute('data-traffic-cop', 'blocked');
            });
            
            // Hide other common ad containers
            const adSelectors = [
                '[class*="ad-"]', '[id*="ad-"]', '[class*="advertisement"]',
                '[class*="adsense"]', '[class*="google-ad"]', '.ad', '#ad',
                '[class*="banner"]', '[id*="banner"]', '[class*="ads"]'
            ];
            
            adSelectors.forEach(selector => {
                document.querySelectorAll(selector).forEach(ad => {
                    ad.style.display = 'none';
                    ad.setAttribute('data-traffic-cop', 'blocked');
                });
            });
            
            // Prevent new AdSense ads from loading
            if (window.adsbygoogle) {
                window.adsbygoogle.forEach(ad => {
                    if (ad.getAttribute('data-ad-status') !== 'filled') {
                        ad.style.display = 'none';
                    }
                });
            }
            
            if (this.config.debug) {
                console.log('🚫 Bot detected - Ads blocked automatically');
            }
        }
        
        showChallenge(analysis) {
            const overlay = document.createElement('div');
            overlay.id = 'traffic-cop-challenge';
            overlay.innerHTML = `
                <div style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
                           background: rgba(0,0,0,0.8); z-index: 999999; display: flex; 
                           align-items: center; justify-content: center; font-family: Arial, sans-serif;">
                    <div style="background: white; padding: 40px; border-radius: 15px; text-align: center; 
                               max-width: 400px; box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
                        <h2 style="margin-top: 0; color: #333;">🛡️ Security Verification</h2>
                        <p style="color: #666; line-height: 1.5;">
                            Our system detected unusual browsing patterns.<br>
                            Please verify you're human to continue.
                        </p>
                        <p style="font-size: 0.9em; color: #999;">
                            Risk Score: ${analysis.riskScore}%<br>
                            Detection: ${analysis.threats.join(', ')}
                            ${analysis.vpnProxy?.isVPN ? '<br>VPN/Proxy detected' : ''}
                        </p>
                        <button onclick="window.trafficCop.passChallenge()" 
                               style="background: #4CAF50; color: white; border: none; padding: 15px 30px; 
                                      border-radius: 8px; font-size: 16px; cursor: pointer; margin: 10px;">
                            ✓ I'm Human
                        </button>
                        <button onclick="window.trafficCop.closeChallenge()" 
                               style="background: #999; color: white; border: none; padding: 15px 30px; 
                                      border-radius: 8px; font-size: 16px; cursor: pointer; margin: 10px;">
                            ✗ Close
                        </button>
                        <br>
                        <small style="color: #999;">Powered by Traffic Cop v2.3</small>
                    </div>
                </div>
            `;
            document.body.appendChild(overlay);
        }
        
        passChallenge() {
            this.closeChallenge();
            this.allowAds();
            this.logEvent('challenge_passed');
            this.triggerEvent('trafficCopChallengePass');
        }
        
        closeChallenge() {
            const overlay = document.getElementById('traffic-cop-challenge');
            if (overlay) {
                overlay.remove();
            }
        }
        
        allowAds() {
            this.isBlocked = false;
            
            // Restore blocked ads
            document.querySelectorAll('[data-traffic-cop="blocked"]').forEach(element => {
                element.style.display = '';
                element.removeAttribute('data-traffic-cop');
            });
            
            // Restore VPN blocked ads
            document.querySelectorAll('[data-traffic-cop-vpn-blocked="true"]').forEach(element => {
                element.style.display = '';
                element.style.visibility = '';
                element.removeAttribute('data-traffic-cop-vpn-blocked');
            });
        }
        
        logEvent(eventType, data = {}) {
            if (this.config.debug) {
                console.log(`📊 Traffic Cop Event: ${eventType}`, data);
            }
            
            try {
                const events = JSON.parse(localStorage.getItem('trafficCopEvents') || '[]');
                events.push({
                    type: eventType,
                    data: data,
                    timestamp: Date.now(),
                    sessionId: this.sessionId
                });
                
                if (events.length > 100) {
                    events.splice(0, events.length - 100);
                }
                
                localStorage.setItem('trafficCopEvents', JSON.stringify(events));
            } catch (e) {
                // Handle localStorage errors gracefully
                if (this.config.debug) {
                    console.warn('Failed to store event:', e);
                }
            }
        }
        
        triggerEvent(eventName, data) {
            const event = new CustomEvent(eventName, { detail: data });
            window.dispatchEvent(event);
        }
        
        storeAnalysis(analysis) {
            try {
                const stored = JSON.parse(localStorage.getItem('trafficCopAnalytics') || '[]');
                stored.push({
                    ...analysis,
                    timestamp: Date.now(),
                    url: window.location.href
                });
                
                if (stored.length > 50) {
                    stored.splice(0, stored.length - 50);
                }
                
                localStorage.setItem('trafficCopAnalytics', JSON.stringify(stored));
            } catch (e) {
                // Handle localStorage errors gracefully
                if (this.config.debug) {
                    console.warn('Failed to store analysis:', e);
                }
            }
        }
        
        generateSessionId() {
            return 'tc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        }
        
        // Manual analysis method
        analyze() {
            return this.analyzeCurrentVisitor();
        }
        
        // Get current visitor data
        getVisitorData() {
            return this.collectVisitorData();
        }
        
        // Get real-time visitor data
        getRealTimeData() {
            return this.visitorSession;
        }
        
        // Get events log
        getEvents() {
            try {
                return JSON.parse(localStorage.getItem('trafficCopEvents') || '[]');
            } catch (e) {
                return [];
            }
        }
        
        // Clear all stored data
        clearData() {
            try {
                localStorage.removeItem('trafficCopEvents');
                localStorage.removeItem('trafficCopAnalytics');
                this.behaviorData = {
                    mouseMovements: [],
                    clicks: [],
                    scrollEvents: [],
                    keystrokes: [],
                    pageInteractions: 0,
                    timeOnPage: 0,
                    deviceFingerprint: null
                };
            } catch (e) {
                if (this.config.debug) {
                    console.warn('Failed to clear data:', e);
                }
            }
        }
        
        // Force VPN detection
        async forceVPNDetection() {
            if (this.config.enableVPNDetection) {
                await this.detectVPNProxy();
                return this.getVPNData();
            }
            return { detected: false, message: 'VPN detection disabled' };
        }
        
        // Update configuration
        updateConfig(newConfig) {
            this.config = { ...this.config, ...newConfig };
            if (this.config.debug) {
                console.log('🔧 Traffic Cop configuration updated:', this.config);
            }
        }
        
        // Get current configuration
        getConfig() {
            return { ...this.config };
        }
        
        // Enable/disable VPN ad blocking
        setVPNAdBlocking(enabled) {
            this.config.blockAdsForVPN = enabled;
            if (enabled && this.vpnDetected && !this.vpnAdBlockingActive) {
                this.activateVPNAdBlocking();
            } else if (!enabled && this.vpnAdBlockingActive) {
                this.vpnAdBlockingActive = false;
                this.allowAds();
            }
        }
        
        // Get blocked scripts list
        getBlockedScripts() {
            return this.blockedScripts;
        }
        
        // Manual script blocking
        blockScript(scriptUrl) {
            if (!this.blockedAdScripts.includes(scriptUrl)) {
                this.blockedAdScripts.push(scriptUrl);
            }
            
            // Remove existing scripts with this URL
            document.querySelectorAll(`script[src*="${scriptUrl}"]`).forEach(script => {
                script.remove();
                this.logVPNAdBlock(scriptUrl, 'manual_block');
            });
        }
        
        // Check if user is currently detected as VPN
        isVPNUser() {
            return this.vpnDetected;
        }
        
        // Check if ads are currently blocked
        areAdsBlocked() {
            return this.adsBlocked || this.vpnAdBlockingActive;
        }
        
        // Get detection confidence
        getDetectionConfidence() {
            return {
                vpn: this.visitorSession.vpnProxyData?.confidence || 0,
                bot: this.behaviorData.deviceFingerprint ? 75 : 0,
                overall: Math.max(
                    this.visitorSession.vpnProxyData?.confidence || 0,
                    this.behaviorData.deviceFingerprint ? 75 : 0
                )
            };
        }
        
        // Destroy SDK instance
        destroy() {
            this.isBlocked = false;
            this.adsBlocked = false;
            this.vpnAdBlockingActive = false;
            this.allowAds();
            
            // Clear the instance
            if (window.trafficCop === this) {
                window.trafficCop = null;
            }
            
            if (this.config.debug) {
                console.log('🛡️ Traffic Cop SDK destroyed');
            }
        }
    }
    
    // Global API
    window.TrafficCop = {
        init: function(apiKey, config) {
            window.trafficCop = new TrafficCopSDK(apiKey, config);
            return window.trafficCop;
        },
        version: '2.3.0',
        SDK: TrafficCopSDK
    };
    
    // Auto-detect if API key is provided via data attribute
    document.addEventListener('DOMContentLoaded', function() {
        const scripts = document.getElementsByTagName('script');
        for (let script of scripts) {
            const apiKey = script.getAttribute('data-traffic-cop-key');
            if (apiKey) {
                const config = {
                    debug: script.getAttribute('data-debug') === 'true',
                    enableVPNDetection: script.getAttribute('data-vpn-detection') !== 'false',
                    blockAdsForVPN: script.getAttribute('data-block-ads-vpn') !== 'false',
                    vpnBlockThreshold: parseInt(script.getAttribute('data-vpn-threshold')) || 65,
                    mode: script.getAttribute('data-mode') || 'block'
                };
                
                new TrafficCopSDK(apiKey, config);
                break;
            }
        }
    });
    
    // Auto-initialize if global config is available
    if (window.TrafficCopConfig && window.TrafficCopConfig.apiKey) {
        window.trafficCop = new TrafficCopSDK(window.TrafficCopConfig.apiKey, window.TrafficCopConfig);
    }
    
})(window);

