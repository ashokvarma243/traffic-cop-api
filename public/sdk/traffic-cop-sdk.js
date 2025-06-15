// traffic-cop-sdk.js - Publisher Integration SDK
(function(window) {
    'use strict';
    
    class TrafficCopSDK {
        constructor(apiKey, config = {}) {
            this.apiKey = apiKey;
            this.config = {
                endpoint: config.endpoint || 'http://localhost:3000/api/v1/analyze',
                mode: config.mode || 'monitor', // monitor, challenge, block
                blockThreshold: config.blockThreshold || 80,
                challengeThreshold: config.challengeThreshold || 60,
                debug: config.debug || false,
                autoProtect: config.autoProtect !== false, // default true
                ...config
            };
            
            this.sessionId = this.generateSessionId();
            this.startTime = Date.now();
            this.isBlocked = false;
            
            if (this.config.autoProtect) {
                this.init();
            }
        }
        
        init() {
            if (this.config.debug) {
                console.log('🛡️ Traffic Cop SDK initialized', this.config);
            }
            
            // Start protection immediately
            this.analyzeCurrentVisitor();
            
            // Set up ongoing monitoring
            this.setupEventListeners();
        }
        
        async analyzeCurrentVisitor() {
            try {
                const visitorData = this.collectVisitorData();
                const response = await this.sendAnalysisRequest(visitorData);
                
                if (response.ok) {
                    const analysis = await response.json();
                    this.handleAnalysisResult(analysis);
                    this.storeAnalysis(analysis);
                } else {
                    if (this.config.debug) {
                        console.warn('Traffic Cop analysis failed:', response.status);
                    }
                }
                
            } catch (error) {
                if (this.config.debug) {
                    console.error('Traffic Cop error:', error);
                }
            }
        }
        
        collectVisitorData() {
            return {
                sessionId: this.sessionId,
                url: window.location.href,
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
                plugins: navigator.plugins.length
            };
        }
        
        async sendAnalysisRequest(data) {
            return fetch(this.config.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`
                },
                body: JSON.stringify(data)
            });
        }
        
        handleAnalysisResult(analysis) {
            if (this.config.debug) {
                console.log('🔍 Analysis result:', analysis);
            }
            
            // Execute protection based on risk level and mode
            switch (analysis.action) {
                case 'block':
                    if (this.config.mode === 'block') {
                        this.blockAds();
                        this.showBlockMessage();
                        this.logEvent('ads_blocked', analysis);
                    }
                    break;
                    
                case 'challenge':
                    if (this.config.mode === 'challenge' || this.config.mode === 'block') {
                        this.showChallenge(analysis);
                        this.logEvent('challenge_shown', analysis);
                    }
                    break;
                    
                default:
                    this.allowAds();
                    this.logEvent('ads_allowed', analysis);
            }
            
            // Trigger custom events for publisher
            this.triggerEvent('trafficCopAnalysis', analysis);
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
                '[class*="adsense"]', '[class*="google-ad"]', '.ad', '#ad'
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
        }
        
        showBlockMessage() {
            if (this.config.showBlockMessage === false) return;
            
            const message = document.createElement('div');
            message.id = 'traffic-cop-block-message';
            message.innerHTML = `
                <div style="position: fixed; top: 20px; right: 20px; background: #f44336; color: white; 
                           padding: 15px; border-radius: 8px; z-index: 999999; font-family: Arial, sans-serif;
                           box-shadow: 0 4px 12px rgba(0,0,0,0.3); max-width: 300px;">
                    <strong>🛡️ Traffic Protection Active</strong><br>
                    <small>Suspicious activity detected. Ads have been blocked to protect this site.</small>
                </div>
            `;
            document.body.appendChild(message);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (message.parentNode) {
                    message.parentNode.removeChild(message);
                }
            }, 5000);
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
                            We've detected unusual activity from your connection.<br>
                            Please verify you're human to continue browsing.
                        </p>
                        <p style="font-size: 0.9em; color: #999;">
                            Risk Score: ${analysis.riskScore}%<br>
                            Session: ${analysis.sessionId.substr(-8)}
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
                        <small style="color: #999;">Powered by Traffic Cop</small>
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
            
            // Restore hidden ads
            document.querySelectorAll('[data-traffic-cop="blocked"]').forEach(element => {
                element.style.display = '';
                element.removeAttribute('data-traffic-cop');
            });
        }
        
        setupEventListeners() {
            // Track user interactions for behavioral analysis
            let clickCount = 0;
            let lastClickTime = 0;
            
            document.addEventListener('click', (event) => {
                if (this.isBlocked) return;
                
                clickCount++;
                const now = Date.now();
                const timeBetweenClicks = now - lastClickTime;
                
                // Detect rapid clicking (possible bot)
                if (timeBetweenClicks < 100 && clickCount > 10) {
                    this.logEvent('rapid_clicking_detected', {
                        clickCount,
                        timeBetweenClicks
                    });
                    
                    // Re-analyze if suspicious behavior detected
                    this.analyzeCurrentVisitor();
                }
                
                lastClickTime = now;
            });
            
            // Monitor page visibility changes
            document.addEventListener('visibilitychange', () => {
                this.logEvent('visibility_change', {
                    hidden: document.hidden,
                    timestamp: Date.now()
                });
            });
        }
        
        logEvent(eventType, data = {}) {
            if (this.config.debug) {
                console.log(`📊 Traffic Cop Event: ${eventType}`, data);
            }
            
            // Store event locally
            const events = JSON.parse(localStorage.getItem('trafficCopEvents') || '[]');
            events.push({
                type: eventType,
                data: data,
                timestamp: Date.now(),
                sessionId: this.sessionId
            });
            
            // Keep only last 100 events
            if (events.length > 100) {
                events.splice(0, events.length - 100);
            }
            
            localStorage.setItem('trafficCopEvents', JSON.stringify(events));
        }
        
        triggerEvent(eventName, data) {
            const event = new CustomEvent(eventName, { detail: data });
            window.dispatchEvent(event);
        }
        
        storeAnalysis(analysis) {
            const stored = JSON.parse(localStorage.getItem('trafficCopAnalytics') || '[]');
            stored.push({
                ...analysis,
                timestamp: Date.now(),
                url: window.location.href
            });
            
            // Keep only last 50 analyses
            if (stored.length > 50) {
                stored.splice(0, stored.length - 50);
            }
            
            localStorage.setItem('trafficCopAnalytics', JSON.stringify(stored));
        }
        
        generateSessionId() {
            return 'tc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        }
        
        // Public API for publishers
        getAnalytics() {
            return JSON.parse(localStorage.getItem('trafficCopAnalytics') || '[]');
        }
        
        getEvents() {
            return JSON.parse(localStorage.getItem('trafficCopEvents') || '[]');
        }
        
        getStats() {
            const analytics = this.getAnalytics();
            const total = analytics.length;
            const blocked = analytics.filter(a => a.action === 'block').length;
            const challenged = analytics.filter(a => a.action === 'challenge').length;
            
            return {
                totalSessions: total,
                blockedSessions: blocked,
                challengedSessions: challenged,
                blockRate: total > 0 ? Math.round((blocked / total) * 100) : 0,
                isCurrentlyBlocked: this.isBlocked
            };
        }
        
        // Manual control methods for publishers
        forceBlock() {
            this.blockAds();
            this.showBlockMessage();
            this.logEvent('manual_block');
        }
        
        forceAllow() {
            this.allowAds();
            this.closeChallenge();
            this.logEvent('manual_allow');
        }
        
        reanalyze() {
            this.analyzeCurrentVisitor();
        }
    }
    
    // Global API
    window.TrafficCop = {
        init: function(apiKey, config) {
            window.trafficCop = new TrafficCopSDK(apiKey, config);
            return window.trafficCop;
        },
        
        version: '1.0.0',
        
        // Quick setup methods
        protect: function(apiKey, mode = 'block') {
            return this.init(apiKey, { mode: mode, debug: false });
        },
        
        monitor: function(apiKey) {
            return this.init(apiKey, { mode: 'monitor', debug: true });
        }
    };
    
    // Auto-initialize if API key is provided in script tag
    const script = document.currentScript;
    if (script && script.getAttribute('data-api-key')) {
        const apiKey = script.getAttribute('data-api-key');
        const mode = script.getAttribute('data-mode') || 'monitor';
        const debug = script.getAttribute('data-debug') === 'true';
        
        window.TrafficCop.init(apiKey, { mode, debug });
    }
    
})(window);

