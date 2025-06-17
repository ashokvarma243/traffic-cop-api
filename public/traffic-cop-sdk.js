// Enhanced Traffic Cop SDK with Automatic Bot Detection
(function(window) {
    'use strict';
    
    class TrafficCopSDK {
        constructor(apiKey, config = {}) {
            this.apiKey = apiKey;
            this.config = {
                endpoint: config.endpoint || 'https://your-vercel-url.vercel.app/api/v1/analyze',
                mode: config.mode || 'block',
                blockThreshold: config.blockThreshold || 80,
                challengeThreshold: config.challengeThreshold || 60,
                debug: config.debug || false,
                autoProtect: config.autoProtect !== false,
                realTimeDetection: config.realTimeDetection !== false
            };
            
            this.sessionId = this.generateSessionId();
            this.startTime = Date.now();
            this.isBlocked = false;
            this.behaviorData = {
                mouseMovements: [],
                clicks: [],
                scrollEvents: [],
                keystrokes: [],
                pageInteractions: 0,
                timeOnPage: 0,
                deviceFingerprint: null
            };
            
            if (this.config.autoProtect) {
                this.init();
            }
        }
        
        init() {
            if (this.config.debug) {
                console.log('🛡️ Traffic Cop SDK initialized with automatic bot detection', this.config);
            }
            
            // Start comprehensive behavior tracking
            this.setupBehaviorTracking();
            
            // Generate device fingerprint
            this.generateDeviceFingerprint();
            
            // Initial analysis
            this.analyzeCurrentVisitor();
            
            // Set up real-time monitoring
            if (this.config.realTimeDetection) {
                this.setupRealTimeMonitoring();
            }
        }
        
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
                
                // Keep only last 20 clicks
                if (this.behaviorData.clicks.length > 20) {
                    this.behaviorData.clicks.shift();
                }
                
                // Check for rapid clicking (bot behavior)
                this.checkRapidClicking();
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
                    downlink: navigator.connection.downlink
                } : null
            };
            
            this.behaviorData.deviceFingerprint = fingerprint;
            
            // Check for bot indicators in fingerprint
            this.checkDeviceBotIndicators(fingerprint);
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
            const botKeywords = ['bot', 'crawler', 'spider', 'scraper', 'headless', 'phantom', 'selenium'];
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
                plugins: navigator.plugins.length,
                
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
                deviceFingerprint: this.behaviorData.deviceFingerprint
            };
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
        
        handleAnalysisResult(analysis, forcedAnalysis = false) {
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
                    if (!forcedAnalysis) {
                        this.allowAds();
                        this.logEvent('ads_allowed', analysis);
                    }
            }
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
                '[class*="banner"]', '[id*="banner"]'
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
        
        showBlockMessage() {
            if (this.config.showBlockMessage === false) return;
            
            const message = document.createElement('div');
            message.id = 'traffic-cop-block-message';
            message.innerHTML = `
                <div style="position: fixed; top: 20px; right: 20px; background: #f44336; color: white; 
                           padding: 15px; border-radius: 8px; z-index: 999999; font-family: Arial, sans-serif;
                           box-shadow: 0 4px 12px rgba(0,0,0,0.3); max-width: 300px;">
                    <strong>🛡️ Bot Traffic Detected</strong><br>
                    <small>Automated traffic blocked to protect this site's ad revenue.</small>
                </div>
            `;
            document.body.appendChild(message);
            
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
                            Our system detected unusual browsing patterns.<br>
                            Please verify you're human to continue.
                        </p>
                        <p style="font-size: 0.9em; color: #999;">
                            Risk Score: ${analysis.riskScore}%<br>
                            Detection: Automated behavior patterns
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
            
            document.querySelectorAll('[data-traffic-cop="blocked"]').forEach(element => {
                element.style.display = '';
                element.removeAttribute('data-traffic-cop');
            });
        }
        
        logEvent(eventType, data = {}) {
            if (this.config.debug) {
                console.log(`📊 Traffic Cop Event: ${eventType}`, data);
            }
            
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
            
            if (stored.length > 50) {
                stored.splice(0, stored.length - 50);
            }
            
            localStorage.setItem('trafficCopAnalytics', JSON.stringify(stored));
        }
        
        generateSessionId() {
            return 'tc_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        }
        
        getStats() {
            const analytics = JSON.parse(localStorage.getItem('trafficCopAnalytics') || '[]');
            const total = analytics.length;
            const blocked = analytics.filter(a => a.action === 'block').length;
            
            return {
                totalSessions: total,
                blockedSessions: blocked,
                blockRate: total > 0 ? Math.round((blocked / total) * 100) : 0,
                isCurrentlyBlocked: this.isBlocked
            };
        }
    }
    
    // Global API
    window.TrafficCop = {
        init: function(apiKey, config) {
            window.trafficCop = new TrafficCopSDK(apiKey, config);
            return window.trafficCop;
        },
        version: '2.0.0'
    };
    
})(window);
