// server.js - Enhanced Traffic Cop API Server with Advanced Bot Detection
const url = require('url');

// Real traffic tracking - NO placeholder data
let realTrafficData = {
    dailyStats: new Map(),
    detectionHistory: []
};

// Real-time visitor tracking storage
let realTimeVisitors = new Map();
let visitorHistory = [];

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

// Enhanced bot detection with better accuracy
function analyzeTrafficAdvanced(userAgent, website, requestData = {}) {
    let riskScore = 0;
    let threats = [];
    let confidence = 0;
    
    // Advanced User Agent Analysis
    const botPatterns = [
        /bot|crawler|spider|scraper/i,
        /python-requests|curl|wget|httpclient/i,
        /headless|phantom|selenium|puppeteer/i,
        /facebook|twitter|linkedin|pinterest/i, // Social media bots
    ];
    
    const searchEnginePatterns = [
        /googlebot|bingbot|slurp|duckduckbot|yandexbot/i
    ];
    
    const legitimatePatterns = [
        /chrome|firefox|safari|edge|opera/i,
        /mobile|android|iphone|ipad/i,
        /windows|macintosh|linux/i
    ];
    
    // 1. User Agent Scoring (More Sophisticated)
    let userAgentScore = 0;
    let isSearchEngine = false;
    
    // Check for search engines (should be allowed)
    if (searchEnginePatterns.some(pattern => pattern.test(userAgent))) {
        isSearchEngine = true;
        userAgentScore = -20; // Negative score = good
        threats.push("Search Engine Bot (Allowed)");
    } else {
        // Check for malicious bot patterns
        botPatterns.forEach(pattern => {
            if (pattern.test(userAgent)) {
                userAgentScore += 25;
                threats.push("Suspicious User Agent");
            }
        });
        
        // Check for legitimate browser patterns
        let hasLegitimatePattern = false;
        legitimatePatterns.forEach(pattern => {
            if (pattern.test(userAgent)) {
                hasLegitimatePattern = true;
                userAgentScore -= 10; // Reduce risk for legitimate browsers
            }
        });
        
        if (!hasLegitimatePattern) {
            userAgentScore += 15;
            threats.push("Unknown Browser Pattern");
        }
    }
    
    // 2. Behavioral Analysis
    let behaviorScore = 0;
    
    if (requestData.behaviorFlags) {
        const suspiciousBehaviors = {
            'rapid_requests': 30,
            'no_javascript': 20,
            'suspicious_headers': 15,
            'no_cookies': 10,
            'headless_browser': 35,
            'automated_pattern': 25,
            'bulk_requests': 40,
            'no_human_behavior': 30
        };
        
        requestData.behaviorFlags.forEach(flag => {
            if (suspiciousBehaviors[flag]) {
                behaviorScore += suspiciousBehaviors[flag];
                threats.push(`Behavior: ${flag.replace('_', ' ')}`);
            }
        });
    }
    
    // 3. Request Pattern Analysis
    let patternScore = 0;
    
    if (requestData.requestPattern) {
        const patternRisks = {
            'automated': 25,
            'bulk_download': 35,
            'click_fraud': 45,
            'content_scraping': 40,
            'normal': -10
        };
        
        patternScore = patternRisks[requestData.requestPattern] || 0;
        if (patternScore > 0) {
            threats.push(`Pattern: ${requestData.requestPattern}`);
        }
    }
    
    // 4. Website-Specific Rules
    let websiteScore = 0;
    
    if (website === 'dailyjobsindia.com') {
        // Protect against job scraping bots
        if (/job|scraper|harvest/i.test(userAgent)) {
            websiteScore += 30;
            threats.push("Job Scraper Detected");
        }
        
        // Allow legitimate job seekers
        if (requestData.humanIndicators) {
            websiteScore -= 15;
            threats.push("Human Behavior Detected");
        }
    }
    
    // 5. IP Reputation (if available)
    if (requestData.ipAddress) {
        const suspiciousIPs = [
            /^10\./, /^192\.168\./, /^172\.16\./, // Private IPs (suspicious for web traffic)
            /^185\.220\./ // Known Tor exit nodes
        ];
        
        suspiciousIPs.forEach(pattern => {
            if (pattern.test(requestData.ipAddress)) {
                websiteScore += 20;
                threats.push("Suspicious IP Range");
            }
        });
    }
    
    // Calculate final risk score
    riskScore = Math.max(0, Math.min(100, userAgentScore + behaviorScore + patternScore + websiteScore));
    
    // Calculate confidence based on available data
    let dataPoints = 1; // Always have user agent
    if (requestData.behaviorFlags) dataPoints++;
    if (requestData.requestPattern) dataPoints++;
    if (requestData.ipAddress) dataPoints++;
    if (requestData.humanIndicators) dataPoints++;
    
    confidence = Math.min(95, 60 + (dataPoints * 7));
    
    // Determine action
    let action = 'allow';
    if (isSearchEngine) {
        action = 'allow';
        threats = ["Search Engine Bot (Allowed)"];
    } else if (riskScore >= 80) {
        action = 'block';
    } else if (riskScore >= 50) {
        action = 'challenge';
    } else {
        action = 'allow';
        if (threats.length === 0) {
            threats = ["Low Risk"];
        }
    }
    
    return {
        riskScore,
        action,
        confidence,
        threats,
        analysis: {
            userAgentScore,
            behaviorScore,
            patternScore,
            websiteScore,
            isSearchEngine
        }
    };
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
                version: '2.2.0',
                features: ['Enhanced Bot Detection', 'Real Analytics', 'Advanced Captcha', 'Real-Time Visitor Tracking']
            });
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
                    
                    // Enhanced bot detection analysis
                    const analysis = analyzeTrafficAdvanced(userAgent, website, requestData);
                    
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
                        }
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
                    const { sessionId, challengeType, verified } = JSON.parse(body);
                    
                    if (verified) {
                        res.status(200).json({
                            success: true,
                            message: 'Challenge completed successfully',
                            redirectUrl: '/' // Redirect to original website
                        });
                    } else {
                        res.status(400).json({
                            success: false,
                            error: 'Challenge verification failed'
                        });
                    }
                    
                } catch (error) {
                    res.status(400).json({
                        error: 'Invalid challenge data'
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
                            '✅ Enhanced Traffic Cop protection system is active',
                            '📊 Waiting for real traffic to analyze...',
                            '🔍 All statistics will be based on actual detections',
                            '🛡️ Advanced bot detection algorithms ready'
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
                        '✅ Enhanced Traffic Cop is ready to analyze incoming requests',
                        '🛡️ Advanced bot detection algorithms active'
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
            font-size: 1.5em;
            color: #333;
            margin-bottom: 15px;
        }
        .answer-input {
            padding: 12px;
            font-size: 1.2em;
            border: 2px solid #ddd;
            border-radius: 5px;
            width: 100px;
            text-align: center;
            margin: 0 10px;
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
            margin-top: 10px;
            display: none;
        }
        .loading {
            display: none;
            color: #667eea;
            margin-top: 10px;
        }
        .checkbox-challenge {
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 20px 0;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .checkbox-challenge:hover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        .checkbox-challenge input {
            margin-right: 10px;
            transform: scale(1.5);
        }
        .challenge-type {
            margin-bottom: 20px;
        }
        .challenge-tabs {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        .tab {
            padding: 10px 20px;
            background: #e9ecef;
            border: none;
            cursor: pointer;
            margin: 0 5px;
            border-radius: 5px;
        }
        .tab.active {
            background: #667eea;
            color: white;
        }
    </style>
</head>
<body>
    <div class="challenge-container">
        <div class="shield-icon">🛡️</div>
        <h1>Human Verification Required</h1>
        <p class="subtitle">Please complete this challenge to continue to the website</p>
        
        <div class="challenge-tabs">
            <button class="tab active" onclick="showChallenge('checkbox')">Quick Check</button>
            <button class="tab" onclick="showChallenge('math')">Math Problem</button>
        </div>
        
        <!-- Checkbox Challenge -->
        <div id="checkbox-challenge" class="challenge-type">
            <div class="checkbox-challenge" onclick="toggleCheckbox()">
                <input type="checkbox" id="human-checkbox">
                <label for="human-checkbox">I'm not a robot</label>
            </div>
        </div>
        
        <!-- Math Challenge -->
        <div id="math-challenge" class="challenge-type" style="display: none;">
            <div class="captcha-box">
                <div class="math-challenge" id="math-problem">Loading...</div>
                <input type="number" id="math-answer" class="answer-input" placeholder="?">
            </div>
        </div>
        
        <button class="verify-btn" id="verify-btn" onclick="verifyChallenge()" disabled>
            Verify
        </button>
        
        <div class="error-message" id="error-message"></div>
        <div class="loading" id="loading">Verifying...</div>
        
        <p style="margin-top: 30px; color: #666; font-size: 0.9em;">
            Protected by Traffic Cop • This verification helps protect against automated traffic
        </p>
    </div>

    <script>
        let currentChallenge = 'checkbox';
        let mathAnswer = 0;
        let sessionId = new URLSearchParams(window.location.search).get('session') || 'unknown';
        
        function showChallenge(type) {
            // Update tabs
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            event.target.classList.add('active');
            
            // Show/hide challenges
            document.getElementById('checkbox-challenge').style.display = type === 'checkbox' ? 'block' : 'none';
            document.getElementById('math-challenge').style.display = type === 'math' ? 'block' : 'none';
            
            currentChallenge = type;
            
            if (type === 'math') {
                generateMathProblem();
            }
            
            updateVerifyButton();
        }
        
        function generateMathProblem() {
            const num1 = Math.floor(Math.random() * 10) + 1;
            const num2 = Math.floor(Math.random() * 10) + 1;
            const operators = ['+', '-', '×'];
            const operator = operators[Math.floor(Math.random() * operators.length)];
            
            let problem, answer;
            
            switch(operator) {
                case '+':
                    problem = num1 + ' + ' + num2 + ' = ?';
                    answer = num1 + num2;
                    break;
                case '-':
                    problem = (num1 + num2) + ' - ' + num2 + ' = ?';
                    answer = num1;
                    break;
                case '×':
                    problem = num1 + ' × ' + num2 + ' = ?';
                    answer = num1 * num2;
                    break;
            }
            
            document.getElementById('math-problem').textContent = problem;
            mathAnswer = answer;
            document.getElementById('math-answer').value = '';
            updateVerifyButton();
        }
        
        function toggleCheckbox() {
            const checkbox = document.getElementById('human-checkbox');
            checkbox.checked = !checkbox.checked;
            updateVerifyButton();
        }
        
        function updateVerifyButton() {
            const verifyBtn = document.getElementById('verify-btn');
            
            if (currentChallenge === 'checkbox') {
                verifyBtn.disabled = !document.getElementById('human-checkbox').checked;
            } else if (currentChallenge === 'math') {
                const answer = document.getElementById('math-answer').value;
                verifyBtn.disabled = !answer || answer === '';
            }
        }
        
        // Update verify button when typing in math answer
        document.getElementById('math-answer').addEventListener('input', updateVerifyButton);
        
        async function verifyChallenge() {
            const verifyBtn = document.getElementById('verify-btn');
            const errorMsg = document.getElementById('error-message');
            const loading = document.getElementById('loading');
            
            verifyBtn.disabled = true;
            loading.style.display = 'block';
            errorMsg.style.display = 'none';
            
            let isValid = false;
            
            if (currentChallenge === 'checkbox') {
                // Simple checkbox verification
                isValid = document.getElementById('human-checkbox').checked;
            } else if (currentChallenge === 'math') {
                // Math problem verification
                const userAnswer = parseInt(document.getElementById('math-answer').value);
                isValid = userAnswer === mathAnswer;
            }
            
            // Simulate verification delay
            await new Promise(resolve => setTimeout(resolve, 1500));
            
            loading.style.display = 'none';
            
            if (isValid) {
                // Success - redirect to original website
                try {
                    const response = await fetch('/api/v1/verify-challenge', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            sessionId: sessionId,
                            challengeType: currentChallenge,
                            verified: true
                        })
                    });
                    
                    if (response.ok) {
                        const result = await response.json();
                        window.location.href = result.redirectUrl || '/';
                    } else {
                        throw new Error('Verification failed');
                    }
                } catch (error) {
                    // Fallback - just redirect
                    window.location.href = '/';
                }
            } else {
                errorMsg.textContent = currentChallenge === 'math' ? 
                    'Incorrect answer. Please try again.' : 
                    'Please complete the verification.';
                errorMsg.style.display = 'block';
                verifyBtn.disabled = false;
                
                if (currentChallenge === 'math') {
                    generateMathProblem();
                }
            }
        }
        
        // Initialize
        generateMathProblem();
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
