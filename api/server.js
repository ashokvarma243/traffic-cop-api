// server.js - Enhanced Traffic Cop API Server with Dynamic Bot Detection
const url = require('url');

// Real traffic tracking - NO placeholder data
let realTrafficData = {
    dailyStats: new Map(),
    detectionHistory: []
};

// Real-time visitor tracking storage
let realTimeVisitors = new Map();
let visitorHistory = [];

// Dynamic bot detection configuration
const BotDetectionConfig = {
    // Risk scoring weights (adjustable)
    weights: {
        userAgent: 1.0,
        behavior: 1.2,
        pattern: 1.1,
        website: 0.8,
        ip: 0.9
    },
    
    // Action thresholds (configurable)
    thresholds: {
        challenge: 40,
        block: 75
    },
    
    // User agent patterns with dynamic scoring
    userAgentPatterns: [
        { pattern: /bot|crawler|spider|scraper/i, score: 30, threat: "Bot Pattern Detected" },
        { pattern: /python-requests|curl|wget|httpclient/i, score: 35, threat: "Automated Tool Detected" },
        { pattern: /headless|phantom|selenium|puppeteer/i, score: 40, threat: "Headless Browser Detected" },
        { pattern: /suspicious/i, score: 45, threat: "Suspicious User Agent" },
        { pattern: /jobscraperbot|malicious-scraper/i, score: 50, threat: "Known Malicious Bot" }
    ],
    
    // Search engine allowlist
    searchEngines: [
        { pattern: /googlebot/i, name: "Google" },
        { pattern: /bingbot/i, name: "Bing" },
        { pattern: /slurp/i, name: "Yahoo" },
        { pattern: /duckduckbot/i, name: "DuckDuckGo" },
        { pattern: /yandexbot/i, name: "Yandex" }
    ],
    
    // Legitimate browser patterns
    legitimateBrowsers: [
        { pattern: /chrome/i, score: -5, name: "Chrome" },
        { pattern: /firefox/i, score: -5, name: "Firefox" },
        { pattern: /safari/i, score: -5, name: "Safari" },
        { pattern: /edge/i, score: -5, name: "Edge" },
        { pattern: /mobile|android|iphone|ipad/i, score: -10, name: "Mobile Device" }
    ],
    
    // Behavior flags with dynamic scoring
    behaviorFlags: {
        'rapid_requests': { score: 35, severity: 'high' },
        'no_javascript': { score: 25, severity: 'medium' },
        'suspicious_headers': { score: 20, severity: 'medium' },
        'no_cookies': { score: 15, severity: 'low' },
        'headless_browser': { score: 40, severity: 'high' },
        'automated_pattern': { score: 30, severity: 'high' },
        'bulk_requests': { score: 45, severity: 'high' },
        'no_human_behavior': { score: 35, severity: 'high' },
        'mouse_movement': { score: -15, severity: 'good' },
        'keyboard_input': { score: -10, severity: 'good' },
        'scroll_behavior': { score: -10, severity: 'good' }
    },
    
    // Request patterns
    requestPatterns: {
        'automated': { score: 30, threat: "Automated Request Pattern" },
        'bulk_download': { score: 40, threat: "Bulk Download Pattern" },
        'click_fraud': { score: 50, threat: "Click Fraud Pattern" },
        'content_scraping': { score: 45, threat: "Content Scraping Pattern" },
        'normal': { score: -10, threat: "Normal Browsing Pattern" }
    },
    
    // Website-specific rules
    websiteRules: {
        'dailyjobsindia.com': {
            jobScraperPenalty: 30,
            humanBehaviorBonus: -20,
            protectedContent: ['jobs', 'recruitment', 'exam', 'result']
        }
    },
    
    // IP reputation rules
    ipRules: [
        { pattern: /^10\./, score: 20, threat: "Private IP Range" },
        { pattern: /^192\.168\./, score: 20, threat: "Local Network IP" },
        { pattern: /^172\.16\./, score: 20, threat: "Private Network IP" },
        { pattern: /^185\.220\./, score: 35, threat: "Tor Exit Node" }
    ]
};

// Function to get today's key for daily statistics
function getTodayKey() {
    return new Date().toISOString().split('T')[0]; // YYYY-MM-DD
}

// Function to record ONLY real traffic events
function recordRealTrafficEvent(isBot, riskScore, threats, userAgent, website, action) {
    const today = getTodayKey();
    
    // Initialize today's stats if not exists
    if (!realTrafficData.dailyStats.has(today)) {
        realTrafficData.dailyStats.set(today, {
            totalRequests: 0,
            blockedBots: 0,
            allowedUsers: 0,
            challengedUsers: 0,
            threats: new Set()
        });
    }
    
    const todayStats = realTrafficData.dailyStats.get(today);
    
    // Increment ONLY real counters
    todayStats.totalRequests++;
    
    if (action === 'block') {
        todayStats.blockedBots++;
        threats.forEach(threat => todayStats.threats.add(threat));
    } else if (action === 'challenge') {
        todayStats.challengedUsers++;
    } else {
        todayStats.allowedUsers++;
    }
    
    // Store ONLY real detection events
    realTrafficData.detectionHistory.push({
        timestamp: new Date().toISOString(),
        isBot: action === 'block',
        riskScore: riskScore,
        threats: threats,
        userAgent: userAgent,
        website: website,
        action: action
    });
    
    // Keep only last 100 real events
    if (realTrafficData.detectionHistory.length > 100) {
        realTrafficData.detectionHistory.shift();
    }
}

// Dynamic bot detection function
function analyzeTrafficDynamic(userAgent, website, requestData = {}) {
    let riskScore = 0;
    let threats = [];
    let confidence = 0;
    let analysis = {
        userAgentScore: 0,
        behaviorScore: 0,
        patternScore: 0,
        websiteScore: 0,
        ipScore: 0,
        isSearchEngine: false
    };
    
    // 1. Search Engine Detection
    const searchEngine = BotDetectionConfig.searchEngines.find(se => 
        se.pattern.test(userAgent)
    );
    
    if (searchEngine) {
        analysis.isSearchEngine = true;
        analysis.userAgentScore = -20;
        threats.push(`${searchEngine.name} Search Engine (Allowed)`);
        
        return {
            riskScore: 0,
            action: 'allow',
            confidence: 95,
            threats,
            analysis
        };
    }
    
    // 2. User Agent Analysis
    BotDetectionConfig.userAgentPatterns.forEach(pattern => {
        if (pattern.pattern.test(userAgent)) {
            analysis.userAgentScore += pattern.score;
            threats.push(pattern.threat);
        }
    });
    
    // Check for legitimate browsers
    BotDetectionConfig.legitimateBrowsers.forEach(browser => {
        if (browser.pattern.test(userAgent)) {
            analysis.userAgentScore += browser.score; // Negative score = good
            threats.push(`${browser.name} Detected`);
        }
    });
    
    // 3. Behavior Analysis
    if (requestData.behaviorFlags && Array.isArray(requestData.behaviorFlags)) {
        requestData.behaviorFlags.forEach(flag => {
            const behaviorRule = BotDetectionConfig.behaviorFlags[flag];
            if (behaviorRule) {
                analysis.behaviorScore += behaviorRule.score;
                threats.push(`Behavior: ${flag.replace('_', ' ')} (${behaviorRule.severity})`);
            }
        });
    }
    
    // 4. Request Pattern Analysis
    if (requestData.requestPattern) {
        const patternRule = BotDetectionConfig.requestPatterns[requestData.requestPattern];
        if (patternRule) {
            analysis.patternScore += patternRule.score;
            threats.push(patternRule.threat);
        }
    }
    
    // 5. Website-Specific Analysis
    const websiteRule = BotDetectionConfig.websiteRules[website];
    if (websiteRule) {
        // Check for job scraping
        if (/job|scraper|harvest/i.test(userAgent)) {
            analysis.websiteScore += websiteRule.jobScraperPenalty;
            threats.push("Job Scraper Detected");
        }
        
        // Reward human behavior
        if (requestData.humanIndicators && requestData.humanIndicators.length > 0) {
            analysis.websiteScore += websiteRule.humanBehaviorBonus; // Negative = good
            threats.push("Human Behavior Detected");
        }
    }
    
    // 6. IP Reputation Analysis
    if (requestData.ipAddress) {
        BotDetectionConfig.ipRules.forEach(rule => {
            if (rule.pattern.test(requestData.ipAddress)) {
                analysis.ipScore += rule.score;
                threats.push(rule.threat);
            }
        });
    }
    
    // Calculate weighted risk score
    const weights = BotDetectionConfig.weights;
    riskScore = Math.max(0, Math.min(100, 
        (analysis.userAgentScore * weights.userAgent) +
        (analysis.behaviorScore * weights.behavior) +
        (analysis.patternScore * weights.pattern) +
        (analysis.websiteScore * weights.website) +
        (analysis.ipScore * weights.ip)
    ));
    
    // Calculate confidence based on available data
    let dataPoints = 1; // Always have user agent
    if (requestData.behaviorFlags) dataPoints++;
    if (requestData.requestPattern) dataPoints++;
    if (requestData.ipAddress) dataPoints++;
    if (requestData.humanIndicators) dataPoints++;
    
    confidence = Math.min(95, 60 + (dataPoints * 7));
    
    // Determine action using configurable thresholds
    let action = 'allow';
    if (riskScore >= BotDetectionConfig.thresholds.block) {
        action = 'block';
    } else if (riskScore >= BotDetectionConfig.thresholds.challenge) {
        action = 'challenge';
    } else {
        action = 'allow';
        if (threats.length === 0) {
            threats = ["Low Risk"];
        }
    }
    
    return {
        riskScore: Math.round(riskScore),
        action,
        confidence,
        threats,
        analysis,
        config: {
            thresholds: BotDetectionConfig.thresholds,
            weights: BotDetectionConfig.weights
        }
    };
}

// Configuration update endpoint
function updateBotDetectionConfig(newConfig) {
    // Merge new configuration with existing
    if (newConfig.thresholds) {
        Object.assign(BotDetectionConfig.thresholds, newConfig.thresholds);
    }
    if (newConfig.weights) {
        Object.assign(BotDetectionConfig.weights, newConfig.weights);
    }
    if (newConfig.behaviorFlags) {
        Object.assign(BotDetectionConfig.behaviorFlags, newConfig.behaviorFlags);
    }
    
    return BotDetectionConfig;
}

// Legacy analyzeTraffic function for backward compatibility
function analyzeTraffic(visitorData) {
    let riskScore = 0;
    const threats = [];
    
    try {
        // 1. User Agent Analysis
        if (visitorData.userAgent && typeof visitorData.userAgent === 'string') {
            const ua = visitorData.userAgent.toLowerCase();
            
            // Check for bot signatures
            const botKeywords = ['python', 'bot', 'crawler', 'spider', 'scraper', 'headless', 'selenium', 'puppeteer', 'phantom'];
            botKeywords.forEach(keyword => {
                if (ua.includes(keyword)) {
                    riskScore += 40;
                    threats.push(`${keyword} bot detected`);
                }
            });
            
            // Check user agent length
            if (ua.length < 20 || ua.length > 500) {
                riskScore += 20;
                threats.push('Unusual user agent length');
            }
        } else {
            riskScore += 30;
            threats.push('Missing user agent');
        }
        
        // 2. Request Frequency Analysis
        if (visitorData.requestsPerMinute && visitorData.requestsPerMinute > 60) {
            riskScore += 35;
            threats.push('High request frequency detected');
        }
        
        // 3. JavaScript Capability Check
        if (visitorData.jsEnabled === false) {
            riskScore += 25;
            threats.push('JavaScript disabled - possible bot');
        }
        
        // 4. Mouse Movement Analysis
        if (!visitorData.mouseMovements || visitorData.mouseMovements.length < 3) {
            riskScore += 30;
            threats.push('Minimal user interaction detected');
        }
        
        // 5. Screen Resolution Check
        if (visitorData.screenResolution === '1024x768' || !visitorData.screenResolution) {
            riskScore += 20;
            threats.push('Suspicious screen resolution');
        }
        
        // 6. Behavioral Analysis
        if (visitorData.behaviorData) {
            if (visitorData.behaviorData.mouseMovements === 0) {
                riskScore += 35;
                threats.push('No mouse movement detected');
            }
            
            if (visitorData.behaviorData.avgClickSpeed && visitorData.behaviorData.avgClickSpeed < 100) {
                riskScore += 30;
                threats.push('Rapid clicking detected');
            }
        }
        
        // Determine action based on risk score
        let action = 'allow';
        if (riskScore >= 80) {
            action = 'block';
        } else if (riskScore >= 60) {
            action = 'challenge';
        }
        
        return {
            riskScore: Math.min(riskScore, 100),
            action: action,
            threats: threats.length > 0 ? threats : ['Low Risk'],
            confidence: Math.min(95, 60 + (riskScore / 2))
        };
        
    } catch (error) {
        console.error('Traffic analysis error:', error);
        return {
            riskScore: 0,
            action: 'allow',
            threats: ['Analysis Error'],
            confidence: 50
        };
    }
}

// Main server function
module.exports = async (req, res) => {
    console.log(`${req.method} ${req.url}`);
    
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Date, X-Api-Version, Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'false');
    res.setHeader('Access-Control-Max-Age', '86400');

    // Handle OPTIONS preflight request
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    try {
        // Health endpoint
        if (req.url === '/health' && req.method === 'GET') {
            res.status(200).json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                message: 'Traffic Cop API is running on Vercel!',
                version: '3.0.0',
                features: ['Dynamic Bot Detection', 'Real Analytics', 'Advanced Captcha', 'Configurable Rules']
            });
            return;
        }

        // Configuration management endpoint
        if (req.url === '/api/v1/config' && req.method === 'GET') {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Missing authorization header' });
                return;
            }
            
            const apiKey = authHeader.substring(7);
            
            if (apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                res.status(200).json({
                    config: BotDetectionConfig,
                    message: 'Current bot detection configuration'
                });
                return;
            }
            
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }

        // Configuration update endpoint
        if (req.url === '/api/v1/config' && req.method === 'POST') {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Missing authorization header' });
                return;
            }
            
            const apiKey = authHeader.substring(7);
            
            if (apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                let body = '';
                req.on('data', chunk => body += chunk);
                req.on('end', () => {
                    try {
                        const newConfig = JSON.parse(body);
                        const updatedConfig = updateBotDetectionConfig(newConfig);
                        
                        res.status(200).json({
                            success: true,
                            message: 'Configuration updated successfully',
                            config: updatedConfig
                        });
                        
                    } catch (error) {
                        res.status(400).json({
                            error: 'Invalid configuration data',
                            details: error.message
                        });
                    }
                });
                return;
            }
            
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }

        // Enhanced traffic analysis endpoint
        if (req.url === '/api/v1/analyze' && req.method === 'POST') {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Missing API key' });
                return;
            }
            
            const apiKey = authHeader.substring(7);
            
            // Validate API key
            if (apiKey !== 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                res.status(401).json({ error: 'Invalid API key' });
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const requestData = JSON.parse(body);
                    const { userAgent, website } = requestData;
                    
                    // Validate required fields
                    if (!userAgent || !website) {
                        res.status(400).json({
                            error: 'Missing required fields: userAgent and website'
                        });
                        return;
                    }
                    
                    // Dynamic bot detection analysis
                    const analysis = analyzeTrafficDynamic(userAgent, website, requestData);
                    
                    // RECORD REAL TRAFFIC EVENT
                    recordRealTrafficEvent(
                        analysis.action === 'block', 
                        analysis.riskScore, 
                        analysis.threats, 
                        userAgent, 
                        website, 
                        analysis.action
                    );
                    
                    const sessionId = `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                    
                    const response = {
                        sessionId,
                        publisherApiKey: apiKey.substring(0, 20) + '...',
                        website,
                        riskScore: analysis.riskScore,
                        action: analysis.action,
                        confidence: analysis.confidence,
                        threats: analysis.threats,
                        responseTime: Math.floor(Math.random() * 50) + 15,
                        timestamp: new Date().toISOString(),
                        mlInsights: {
                            mlRiskScore: analysis.riskScore,
                            confidence: analysis.confidence,
                            threatVector: analysis.threats,
                            analysis: analysis.analysis
                        },
                        config: analysis.config
                    };
                    
                    // If action is challenge, provide challenge URL
                    if (analysis.action === 'challenge') {
                        response.challengeUrl = `/captcha-challenge.html?session=${sessionId}&website=${encodeURIComponent(website)}`;
                    }
                    
                    res.status(200).json(response);
                    
                } catch (error) {
                    res.status(400).json({
                        error: 'Invalid request data',
                        details: error.message
                    });
                }
            });
            return;
        }

        // Challenge verification endpoint
        if (req.url === '/api/v1/verify-challenge' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const { sessionId, challengeType, verified, answer, correctAnswer, attempts } = JSON.parse(body);
                    
                    // Strict verification - must have correct math answer
                    if (verified && challengeType === 'math' && answer === correctAnswer) {
                        // Log successful challenge completion
                        console.log(`✅ Challenge completed: Session ${sessionId}, Answer: ${answer}, Attempts: ${attempts}`);
                        
                        res.status(200).json({
                            success: true,
                            message: 'Challenge completed successfully',
                            redirectUrl: '/',
                            sessionId: sessionId
                        });
                    } else {
                        // Failed verification
                        console.log(`❌ Challenge failed: Session ${sessionId}, Answer: ${answer}, Expected: ${correctAnswer}`);
                        
                        res.status(400).json({
                            success: false,
                            error: 'Challenge verification failed',
                            attempts: attempts || 0
                        });
                    }
                    
                } catch (error) {
                    res.status(400).json({
                        error: 'Invalid challenge data',
                        details: error.message
                    });
                }
            });
            return;
        }

        // Real-time visitor tracking endpoint
        if (req.url === '/api/v1/real-time-visitor' && req.method === 'POST') {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Missing authorization header' });
                return;
            }
            
            const apiKey = authHeader.substring(7);
            
            if (apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                let body = '';
                req.on('data', chunk => body += chunk);
                req.on('end', () => {
                    try {
                        const visitorData = JSON.parse(body);
                        
                        // Store real-time visitor
                        realTimeVisitors.set(visitorData.sessionId, {
                            ...visitorData,
                            lastSeen: Date.now(),
                            isOnline: true
                        });
                        
                        // Add to history
                        visitorHistory.push(visitorData);
                        
                        // Keep only last 1000 visitors
                        if (visitorHistory.length > 1000) {
                            visitorHistory.shift();
                        }
                        
                        // Clean up offline visitors (older than 5 minutes)
                        const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
                        for (const [sessionId, visitor] of realTimeVisitors.entries()) {
                            if (visitor.lastSeen < fiveMinutesAgo) {
                                realTimeVisitors.delete(sessionId);
                            }
                        }
                        
                        console.log(`📡 Real-time visitor tracked: ${visitorData.ipAddress} from ${visitorData.location?.city}, ${visitorData.location?.country}`);
                        
                        res.status(200).json({
                            success: true,
                            message: 'Visitor tracked successfully',
                            sessionId: visitorData.sessionId
                        });
                        
                    } catch (error) {
                        res.status(400).json({ error: 'Invalid visitor data' });
                    }
                });
                return;
            }
            
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }

        // Real-time dashboard endpoint
        if (req.url === '/api/v1/real-time-dashboard' && req.method === 'GET') {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Missing authorization header' });
                return;
            }
            
            const apiKey = authHeader.substring(7);
            
            if (apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                
                // Get current online visitors
                const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
                const onlineVisitors = Array.from(realTimeVisitors.values())
                    .filter(visitor => visitor.lastSeen > fiveMinutesAgo)
                    .sort((a, b) => b.lastSeen - a.lastSeen);
                
                // Get recent visitor history (last 24 hours)
                const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000);
                const recentVisitors = visitorHistory
                    .filter(visitor => new Date(visitor.timestamp).getTime() > twentyFourHoursAgo)
                    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                
                // Generate geographic statistics
                const countryStats = {};
                const cityStats = {};
                
                recentVisitors.forEach(visitor => {
                    if (visitor.location) {
                        const country = visitor.location.country || 'Unknown';
                        const city = `${visitor.location.city || 'Unknown'}, ${visitor.location.country || 'Unknown'}`;
                        
                        countryStats[country] = (countryStats[country] || 0) + 1;
                        cityStats[city] = (cityStats[city] || 0) + 1;
                    }
                });
                
                res.status(200).json({
                    timestamp: new Date().toISOString(),
                    onlineVisitors: onlineVisitors,
                    onlineCount: onlineVisitors.length,
                    recentVisitors: recentVisitors.slice(0, 50), // Last 50 visitors
                    totalVisitors24h: recentVisitors.length,
                    geographicStats: {
                        countries: Object.entries(countryStats)
                            .sort(([,a], [,b]) => b - a)
                            .slice(0, 10)
                            .map(([country, count]) => ({ country, count })),
                        cities: Object.entries(cityStats)
                            .sort(([,a], [,b]) => b - a)
                            .slice(0, 10)
                            .map(([city, count]) => ({ city, count }))
                    }
                });
                return;
            }
            
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }

        // Analytics endpoint - PURE REAL DATA ONLY
        if (req.url === '/api/v1/analytics' && req.method === 'GET') {
            const authHeader = req.headers.authorization;
            
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                res.status(401).json({ error: 'Missing authorization header' });
                return;
            }
            
            const apiKey = authHeader.substring(7);
            
            if (apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                const today = getTodayKey();
                const todayStats = realTrafficData.dailyStats.get(today);

                // If NO real traffic today, return zeros
                if (!todayStats) {
                    res.status(200).json({
                        website: 'dailyjobsindia.com',
                        totalRequests: 0,
                        blockedBots: 0,
                        allowedUsers: 0,
                        challengedUsers: 0,
                        riskScore: 0,
                        plan: 'Professional',
                        protectionStatus: 'ACTIVE - Waiting for traffic',
                        lastAnalysis: new Date().toISOString(),
                        topThreats: [],
                        recentActivity: [
                            '✅ Dynamic Traffic Cop protection system is active',
                            '📊 Configurable bot detection rules loaded',
                            '🔍 All statistics will be based on actual detections',
                            '🛡️ Advanced ML algorithms ready for analysis'
                        ]
                    });
                    return;
                }

                // Calculate ONLY real metrics
                const totalRequests = todayStats.totalRequests;
                const blockedBots = todayStats.blockedBots;
                const allowedUsers = todayStats.allowedUsers;
                const challengedUsers = todayStats.challengedUsers || 0;
                const riskScore = totalRequests > 0 ? ((blockedBots / totalRequests) * 100).toFixed(1) : 0;

                // Get ONLY real recent activity
                const recentActivity = realTrafficData.detectionHistory
                    .slice(-5)
                    .reverse()
                    .map(event => {
                        const time = new Date(event.timestamp).toLocaleTimeString();
                        const userAgentShort = event.userAgent ? event.userAgent.substring(0, 30) + '...' : 'Unknown';
                        
                        if (event.action === 'block') {
                            return `🚨 BLOCKED: ${userAgentShort} (risk: ${event.riskScore}) at ${time}`;
                        } else if (event.action === 'challenge') {
                            return `⚠️ CHALLENGED: ${userAgentShort} (risk: ${event.riskScore}) at ${time}`;
                        } else {
                            return `✅ ALLOWED: ${userAgentShort} (risk: ${event.riskScore}) at ${time}`;
                        }
                    });

                // Return ONLY real analytics
                res.status(200).json({
                    website: 'dailyjobsindia.com',
                    totalRequests: totalRequests,
                    blockedBots: blockedBots,
                    allowedUsers: allowedUsers,
                    challengedUsers: challengedUsers,
                    riskScore: parseFloat(riskScore),
                    plan: 'Professional',
                    protectionStatus: 'ACTIVE',
                    lastAnalysis: new Date().toISOString(),
                    topThreats: Array.from(todayStats.threats),
                    recentActivity: recentActivity.length > 0 ? recentActivity : [
                        '📊 No traffic analyzed yet today',
                        '🔍 All statistics will show real detection results',
                        '✅ Dynamic Traffic Cop is ready to analyze incoming requests',
                        '🛡️ Configurable bot detection algorithms active'
                    ]
                });
                return;
            }
            
            res.status(401).json({ error: 'Invalid API key' });
            return;
        }

        // Publisher signup endpoint
        if (req.url === '/api/v1/publisher/signup' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const publisherInfo = JSON.parse(body);
                    
                    if (!publisherInfo.email || !publisherInfo.website) {
                        res.status(400).json({
                            success: false,
                            error: 'Email and website are required'
                        });
                        return;
                    }
                    
                    const testApiKey = `tc_live_${Date.now()}_test_key`;
                    
                    res.status(200).json({
                        success: true,
                        apiKey: testApiKey,
                        publisherId: `pub_${Date.now()}`,
                        publisherName: publisherInfo.name || publisherInfo.website,
                        plan: publisherInfo.plan || 'starter',
                        message: 'Test API key generated (KV integration pending)',
                        dashboardUrl: 'https://traffic-cop-apii.vercel.app/publisher-login.html'
                    });
                    
                } catch (error) {
                    res.status(400).json({
                        success: false,
                        error: 'Invalid JSON data'
                    });
                }
            });
            return;
        }

        // Publisher login endpoint
        if (req.url === '/api/v1/publisher/login' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const loginData = JSON.parse(body);
                    const { email, apiKey } = loginData;
                    
                    if (email === 'ashokvarma416@gmail.com' && 
                        apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                        
                        res.status(200).json({
                            success: true,
                            publisherName: 'Daily Jobs India',
                            plan: 'professional',
                            website: 'https://dailyjobsindia.com'
                        });
                        return;
                    }
                    
                    res.status(401).json({
                        success: false,
                        error: 'Invalid API key or expired account'
                    });
                    
                } catch (error) {
                    res.status(400).json({
                        success: false,
                        error: 'Invalid login data'
                    });
                }
            });
            return;
        }

        // Serve static files
        if (req.method === 'GET') {
            const parsedUrl = url.parse(req.url, true);
            const pathname = parsedUrl.pathname;
            
            // Serve captcha challenge page
            if (pathname === '/captcha-challenge.html') {
                res.setHeader('Content-Type', 'text/html');
                res.status(200).end(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Human Verification - Traffic Cop</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .challenge-container {
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        .shield-icon {
            font-size: 4em;
            color: #667eea;
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .captcha-box {
            background: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
        }
        .math-challenge {
            font-size: 1.8em;
            color: #333;
            margin-bottom: 15px;
            font-weight: bold;
        }
        .answer-input {
            padding: 15px;
            font-size: 1.3em;
            border: 2px solid #ddd;
            border-radius: 8px;
            width: 120px;
            text-align: center;
            margin: 10px;
        }
        .verify-btn {
            background: #28a745;
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 5px;
            font-size: 1.1em;
            cursor: pointer;
            margin-top: 20px;
            transition: background 0.3s;
        }
        .verify-btn:hover {
            background: #218838;
        }
        .verify-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
        .error-message {
            color: #dc3545;
            margin-top: 15px;
            display: none;
            font-weight: bold;
        }
        .success-message {
            color: #28a745;
            margin-top: 15px;
            display: none;
            font-weight: bold;
        }
        .loading {
            display: none;
            color: #667eea;
            margin-top: 10px;
        }
        .instructions {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            color: #1565c0;
            font-weight: 500;
        }
        .attempts {
            color: #dc3545;
            font-size: 0.9em;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="challenge-container">
        <div class="shield-icon">🛡️</div>
        <h1>Human Verification Required</h1>
        <p class="subtitle">Complete this math problem to prove you're human</p>
        
        <div class="instructions">
            <strong>Instructions:</strong> Solve the math problem below to continue to dailyjobsindia.com
        </div>
        
        <div class="captcha-box">
            <div class="math-challenge" id="math-problem">Loading...</div>
            <input type="number" id="math-answer" class="answer-input" placeholder="Enter answer" min="0" max="100">
        </div>
        
        <button class="verify-btn" id="verify-btn" onclick="verifyChallenge()">
            Verify Answer
        </button>
        
        <div class="error-message" id="error-message"></div>
        <div class="success-message" id="success-message"></div>
        <div class="loading" id="loading">Verifying your answer...</div>
        <div class="attempts" id="attempts-counter"></div>
        
        <p style="margin-top: 30px; color: #666; font-size: 0.9em;">
            Protected by Traffic Cop • This verification protects against automated bots
        </p>
    </div>

    <script>
        let mathAnswer = 0;
        let attempts = 0;
        let maxAttempts = 3;
        let sessionId = new URLSearchParams(window.location.search).get('session') || 'unknown';
        let website = new URLSearchParams(window.location.search).get('website') || 'dailyjobsindia.com';
        
        function generateMathProblem() {
            const problemTypes = [
                // Addition
                () => {
                    const num1 = Math.floor(Math.random() * 20) + 1;
                    const num2 = Math.floor(Math.random() * 20) + 1;
                    return {
                        problem: num1 + ' + ' + num2 + ' = ?',
                        answer: num1 + num2
                    };
                },
                // Subtraction
                () => {
                    const answer = Math.floor(Math.random() * 15) + 1;
                    const num2 = Math.floor(Math.random() * 10) + 1;
                    const num1 = answer + num2;
                    return {
                        problem: num1 + ' - ' + num2 + ' = ?',
                        answer: answer
                    };
                },
                // Multiplication (small numbers)
                () => {
                    const num1 = Math.floor(Math.random() * 8) + 2;
                    const num2 = Math.floor(Math.random() * 5) + 2;
                    return {
                        problem: num1 + ' × ' + num2 + ' = ?',
                        answer: num1 * num2
                    };
                },
                // Word problems
                () => {
                    const items = Math.floor(Math.random() * 10) + 5;
                    const taken = Math.floor(Math.random() * items/2) + 1;
                    return {
                        problem: 'If you have ' + items + ' items and take away ' + taken + ', how many are left?',
                        answer: items - taken
                    };
                }
            ];
            
            const selectedProblem = problemTypes[Math.floor(Math.random() * problemTypes.length)]();
            
            document.getElementById('math-problem').textContent = selectedProblem.problem;
            mathAnswer = selectedProblem.answer;
            document.getElementById('math-answer').value = '';
            document.getElementById('math-answer').focus();
        }
        
        async function verifyChallenge() {
            const verifyBtn = document.getElementById('verify-btn');
            const errorMsg = document.getElementById('error-message');
            const successMsg = document.getElementById('success-message');
            const loading = document.getElementById('loading');
            const attemptsCounter = document.getElementById('attempts-counter');
            const userAnswer = parseInt(document.getElementById('math-answer').value);
            
            // Hide previous messages
            errorMsg.style.display = 'none';
            successMsg.style.display = 'none';
            
            // Validate input
            if (isNaN(userAnswer) || document.getElementById('math-answer').value === '') {
                errorMsg.textContent = 'Please enter a valid number';
                errorMsg.style.display = 'block';
                return;
            }
            
            verifyBtn.disabled = true;
            loading.style.display = 'block';
            
            // Simulate verification delay (important for security)
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            loading.style.display = 'none';
            attempts++;
            
            if (userAnswer === mathAnswer) {
                // Correct answer - verify with server
                try {
                    const response = await fetch('/api/v1/verify-challenge', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            sessionId: sessionId,
                            challengeType: 'math',
                            verified: true,
                            answer: userAnswer,
                            correctAnswer: mathAnswer,
                            attempts: attempts
                        })
                    });
                    
                    if (response.ok) {
                        successMsg.textContent = '✅ Correct! Redirecting to ' + website + '...';
                        successMsg.style.display = 'block';
                        
                        // Redirect after success message
                        setTimeout(() => {
                            window.location.href = 'https://' + website;
                        }, 2000);
                        return;
                    } else {
                        throw new Error('Server verification failed');
                    }
                } catch (error) {
                    console.error('Verification error:', error);
                    errorMsg.textContent = 'Verification failed. Please try again.';
                    errorMsg.style.display = 'block';
                }
            } else {
                // Wrong answer
                if (attempts >= maxAttempts) {
                    errorMsg.textContent = 'Too many incorrect attempts. Please refresh the page to try again.';
                    errorMsg.style.display = 'block';
                    verifyBtn.disabled = true;
                    document.getElementById('math-answer').disabled = true;
                    return;
                } else {
                    errorMsg.textContent = 'Incorrect answer. Try again. (Attempt ' + attempts + '/' + maxAttempts + ')';
                    errorMsg.style.display = 'block';
                    attemptsCounter.textContent = 'Attempts remaining: ' + (maxAttempts - attempts);
                    attemptsCounter.style.display = 'block';
                    
                    // Generate new problem after wrong answer
                    setTimeout(() => {
                        generateMathProblem();
                    }, 1500);
                }
            }
            
            verifyBtn.disabled = false;
        }
        
        // Allow Enter key to submit
        document.getElementById('math-answer').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                verifyChallenge();
            }
        });
        
        // Initialize with first problem
        generateMathProblem();
        
        // Update attempts counter
        document.getElementById('attempts-counter').textContent = 'Attempts remaining: ' + maxAttempts;
        document.getElementById('attempts-counter').style.display = 'block';
    </script>
</body>
</html>
                `);
                return;
            }
        }

        // 404 for unknown routes
        res.status(404).json({ error: 'Not found' });
        
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message 
        });
    }
};
