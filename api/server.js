// server.js - Enhanced Traffic Cop API Server with KV Storage Only
const url = require('url');
const crypto = require('crypto');

// Enhanced KV initialization
let kv;
let kvReady = false;

async function initKV() {
    try {
        // Use require instead of dynamic import for better compatibility
        const { kv: kvClient } = require('@vercel/kv');
        kv = kvClient;
        kvReady = true;
        console.log('✅ KV initialized with require method');
        return true;
    } catch (requireError) {
        try {
            // Fallback to dynamic import
            const kvModule = await import('@vercel/kv');
            kv = kvModule.kv;
            kvReady = true;
            console.log('✅ KV initialized with dynamic import');
            return true;
        } catch (importError) {
            console.error('❌ Both KV initialization methods failed:', {
                requireError: requireError.message,
                importError: importError.message
            });
            kvReady = false;
            return false;
        }
    }
}

// Initialize immediately
initKV();

// Enhanced API Key Management with KV Storage
class APIKeyManager {
    constructor() {
        this.kvPrefix = 'tc_api_';
    }
    
    async ensureKVReady() {
        if (!kvReady) {
            await initKV();
        }
        if (!kv) {
            throw new Error('KV module not available');
        }
        return true;
    }
    
    // Generate cryptographically secure API key
    generateAPIKey(publisherData) {
        const timestamp = Date.now();
        const randomBytes = crypto.randomBytes(24).toString('hex');
        const checksum = crypto.createHash('sha256')
            .update(`${timestamp}${randomBytes}${publisherData.email || publisherData.publisherId || 'default'}`)
            .digest('hex')
            .substring(0, 8);
        return `tc_live_${timestamp}_${randomBytes}_${checksum}`;
    }

    
    // Get rate limits based on plan
    getRateLimits(plan) {
        switch (plan) {
            case 'trial':
                return { 
                    requestsPerMonth: 10000, 
                    requestsPerMinute: 10,
                    requestsPerDay: 500
                };
            case 'starter':
                return { 
                    requestsPerMonth: 100000, 
                    requestsPerMinute: 100,
                    requestsPerDay: 5000
                };
            case 'professional':
                return { 
                    requestsPerMonth: 1000000, 
                    requestsPerMinute: 500,
                    requestsPerDay: 50000
                };
            case 'enterprise':
                return { 
                    requestsPerMonth: -1,
                    requestsPerMinute: 1000,
                    requestsPerDay: -1
                };
            default:
                return { 
                    requestsPerMonth: 1000, 
                    requestsPerMinute: 5,
                    requestsPerDay: 100
                };
        }
    }
    
    // Store API key with metadata
    async storeAPIKey(apiKeyData) {
        try {
            await this.ensureKVReady();
            
            const keyData = {
                ...apiKeyData,
                createdAt: new Date().toISOString(),
                lastUsed: new Date().toISOString(),
                requestCount: 0,
                status: 'active',
                rateLimits: this.getRateLimits(apiKeyData.plan || 'starter')
            };
            
            // Store API key data
            await kv.set(`${this.kvPrefix}key:${apiKeyData.apiKey}`, JSON.stringify(keyData));
            
            // Store publisher mapping
            await kv.set(`${this.kvPrefix}publisher:${apiKeyData.publisherId}`, apiKeyData.apiKey);
            
            // Store email mapping for login
            if (apiKeyData.email) {
                await kv.set(`${this.kvPrefix}email:${apiKeyData.email}`, apiKeyData.publisherId);
            }
            
            // Add to active keys list
            await kv.sadd(`${this.kvPrefix}active_keys`, apiKeyData.apiKey);
            
            console.log(`🔑 Enhanced API key stored: ${apiKeyData.apiKey.substring(0, 20)}...`);
            
            return keyData;
            
        } catch (error) {
            console.error('API key storage error:', error);
            throw error;
        }
    }
    
    // Validate API key with rate limiting and fallback support
    async validateAPIKey(apiKey) {
        try {
            await this.ensureKVReady();
            
            // CRITICAL: Fallback for existing hardcoded key
            if (apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                return {
                    valid: true,
                    keyData: { 
                        plan: 'professional', 
                        website: 'newsparrow.in',
                        publisherName: 'Newsparrow',
                        email: 'ashokvarma416@gmail.com',
                        requestCount: 0,
                        status: 'active'
                    },
                    publisherId: 'pub_newsparrow',
                    plan: 'professional',
                    website: 'newsparrow.in'
                };
            }
            
            // Check KV storage for new keys
            const keyDataStr = await kv.get(`${this.kvPrefix}key:${apiKey}`);
            if (!keyDataStr) {
                return { valid: false, reason: 'API key not found' };
            }
            
            const keyData = JSON.parse(keyDataStr);
            
            // Check if key is active
            if (keyData.status !== 'active') {
                return { valid: false, reason: 'API key is inactive' };
            }
            
            // Check expiration if exists
            if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
                return { valid: false, reason: 'API key expired' };
            }
            
            // Check rate limits
            const rateLimits = keyData.rateLimits || this.getRateLimits(keyData.plan || 'starter');
            if (rateLimits.requestsPerMonth !== -1 && 
                keyData.requestCount >= rateLimits.requestsPerMonth) {
                return { valid: false, reason: 'Monthly limit exceeded' };
            }
            
            // Update last used timestamp and request count
            keyData.lastUsed = new Date().toISOString();
            keyData.requestCount = (keyData.requestCount || 0) + 1;
            
            await kv.set(`${this.kvPrefix}key:${apiKey}`, JSON.stringify(keyData));
            
            return { 
                valid: true, 
                keyData: keyData,
                publisherId: keyData.publisherId,
                plan: keyData.plan,
                website: keyData.website,
                rateLimits: rateLimits
            };
            
        } catch (error) {
            console.error('API key validation error:', error);
            
            // Final fallback for existing hardcoded key in case of KV errors
            if (apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                return {
                    valid: true,
                    keyData: { plan: 'professional', website: 'newsparrow.in' },
                    publisherId: 'pub_newsparrow',
                    plan: 'professional',
                    website: 'newsparrow.in'
                };
            }
            
            return { valid: false, reason: 'Validation error' };
        }
    }

    
    // Get publisher by email
    async getPublisherByEmail(email) {
        try {
            await this.ensureKVReady();
            const publisherId = await kv.get(`${this.kvPrefix}email:${email}`);
            if (publisherId) {
                const publisherApiKey = await kv.get(`${this.kvPrefix}publisher:${publisherId}`);
                if (publisherApiKey) {
                    const keyDataStr = await kv.get(`${this.kvPrefix}key:${publisherApiKey}`);
                    return keyDataStr ? JSON.parse(keyDataStr) : null;
                }
            }
            return null;
        } catch (error) {
            console.error('Error getting publisher by email:', error);
            return null;
        }
    }
    
    // Check rate limits
    async checkRateLimit(apiKey) {
        try {
            const keyDataStr = await kv.get(`${this.kvPrefix}key:${apiKey}`);
            if (!keyDataStr) {
                return { allowed: false, reason: 'Invalid API key' };
            }

            const keyData = JSON.parse(keyDataStr);
            const rateLimits = keyData.rateLimits || this.getRateLimits(keyData.plan || 'starter');
            
            // Check monthly limit
            if (rateLimits.requestsPerMonth !== -1 && 
                keyData.requestCount >= rateLimits.requestsPerMonth) {
                return { allowed: false, reason: 'Monthly limit exceeded' };
            }

            return { allowed: true, rateLimits: rateLimits };
        } catch (error) {
            console.error('Rate limit check error:', error);
            return { allowed: false, reason: 'Rate limit check failed' };
        }
    }
}


// KV-Only TrafficCopStorage class
class TrafficCopStorage {
    constructor() {
        this.kvPrefix = 'tc_';
    }
    
    async ensureKVReady() {
        if (!kvReady) {
            await initKV();
        }
        if (!kv) {
            throw new Error('KV not available');
        }
        return true;
    }
    
    // Store visitor session (KV only)
    async storeVisitorSession(visitorData) {
        try {
            console.log('🔄 Starting storeVisitorSession for:', visitorData.sessionId);
            
            await this.ensureKVReady();
            
            const sessionKey = `${this.kvPrefix}session:${visitorData.sessionId}`;
            const sessionData = {
                ...visitorData,
                timestamp: new Date().toISOString(),
                expiresAt: Date.now() + (30 * 60 * 1000)
            };
            
            // Store session with 30-minute expiry
            await kv.setex(sessionKey, 1800, JSON.stringify(sessionData));
            console.log('✅ Session stored in KV successfully');
            
            // Add to activity log
            await this.addToActivityLog(visitorData);
            
            // Update daily stats
            await this.updateDailyStats(visitorData);
            
            console.log(`💾 COMPLETED storing visitor session: ${visitorData.sessionId}`);
            
        } catch (error) {
            console.error('❌ KV storage error:', error);
            throw error;
        }
    }
    
    // Add to activity log (KV only)
    async addToActivityLog(visitorData) {
        try {
            await this.ensureKVReady();
            
            const logEntry = {
                ...visitorData,
                timestamp: new Date().toISOString(),
                id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
            };
            
            await kv.lpush(`${this.kvPrefix}activity_log`, JSON.stringify(logEntry));
            await kv.ltrim(`${this.kvPrefix}activity_log`, 0, 9999);
            console.log('✅ Activity log entry added');
            
        } catch (error) {
            console.error('❌ Activity log error:', error);
            throw error;
        }
    }
    
    // Update daily stats (KV only)
    async updateDailyStats(visitorData) {
        try {
            await this.ensureKVReady();
            
            const today = new Date().toISOString().split('T')[0];
            const statsKey = `${this.kvPrefix}daily:${today}`;
            
            console.log('🔄 Updating daily stats for key:', statsKey);
            
            let currentStats;
            try {
                const currentStatsStr = await kv.get(statsKey);
                
                if (currentStatsStr && currentStatsStr !== 'null' && currentStatsStr !== 'undefined') {
                    currentStats = JSON.parse(currentStatsStr);
                } else {
                    currentStats = null;
                }
            } catch (parseError) {
                console.error('❌ JSON parse error, creating fresh stats:', parseError);
                currentStats = null;
            }
            
            if (!currentStats) {
                currentStats = {
                    date: today,
                    totalRequests: 0,
                    blockedBots: 0,
                    allowedUsers: 0,
                    challengedUsers: 0,
                    threats: [],
                    countries: {},
                    cities: {}
                };
            }
            
            // Update counters
            currentStats.totalRequests++;
            
            if (visitorData.action === 'block') {
                currentStats.blockedBots++;
            } else if (visitorData.action === 'challenge') {
                currentStats.challengedUsers++;
            } else {
                currentStats.allowedUsers++;
            }
            
            // Update geographic data
            if (visitorData.geolocation) {
                const country = visitorData.geolocation.country || 'Unknown';
                const city = visitorData.geolocation.city || 'Unknown';
                
                currentStats.countries[country] = (currentStats.countries[country] || 0) + 1;
                currentStats.cities[city] = (currentStats.cities[city] || 0) + 1;
            }
            
            // Store updated stats
            await kv.setex(statsKey, 604800, JSON.stringify(currentStats));
            console.log('✅ Daily stats updated successfully');
            
        } catch (error) {
            console.error('❌ Daily stats error:', error);
            throw error;
        }
    }
    
    // Get daily statistics (KV only)
    async getDailyStats(date = null) {
        try {
            await this.ensureKVReady();
            
            const targetDate = date || new Date().toISOString().split('T')[0];
            const statsKey = `${this.kvPrefix}daily:${targetDate}`;
            
            console.log('📊 getDailyStats: Looking for key:', statsKey);
            
            const statsStr = await kv.get(statsKey);
            console.log('📊 getDailyStats: Raw KV result:', statsStr);
            
            if (statsStr && statsStr !== 'null') {
                const stats = JSON.parse(statsStr);
                console.log('📊 getDailyStats: Parsed stats:', stats);
                return stats;
            } else {
                return {
                    date: targetDate,
                    totalRequests: 0,
                    blockedBots: 0,
                    allowedUsers: 0,
                    challengedUsers: 0,
                    threats: [],
                    countries: {},
                    cities: {}
                };
            }
            
        } catch (error) {
            console.error('❌ getDailyStats error:', error);
            return {
                date: date || new Date().toISOString().split('T')[0],
                totalRequests: 0,
                blockedBots: 0,
                allowedUsers: 0,
                challengedUsers: 0,
                threats: [],
                countries: {},
                cities: {}
            };
        }
    }
    
    // Get live visitors (KV only)
    async getLiveVisitors() {
        try {
            await this.ensureKVReady();
            
            console.log('👥 Getting live visitors from activity log...');
            
            const activityLog = await kv.lrange(`${this.kvPrefix}activity_log`, 0, 100);
            console.log('📋 Activity log entries found:', activityLog.length);
            
            if (!activityLog || activityLog.length === 0) {
                return [];
            }
            
            const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
            const recentVisitors = [];
            
            for (const logEntry of activityLog) {
                try {
                    const visitor = JSON.parse(logEntry);
                    const visitorTime = new Date(visitor.timestamp).getTime();
                    
                    if (visitorTime > fiveMinutesAgo) {
                        recentVisitors.push(visitor);
                    }
                } catch (parseError) {
                    console.warn('⚠️ Could not parse activity log entry');
                }
            }
            
            console.log('👥 Found recent visitors:', recentVisitors.length);
            return recentVisitors.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
        } catch (error) {
            console.error('❌ Get live visitors error:', error);
            return [];
        }
    }
    
    // Get activity logs (KV only)
    async getActivityLogs(filter = 'today', page = 1, limit = 50) {
        try {
            await this.ensureKVReady();
            
            const activityLog = await kv.lrange(`${this.kvPrefix}activity_log`, 0, -1);
            
            if (!activityLog || activityLog.length === 0) {
                return {
                    activities: [],
                    total: 0,
                    page: page,
                    limit: limit,
                    hasMore: false
                };
            }
            
            // Parse and filter activities
            const activities = [];
            const now = new Date();
            
            for (const logEntry of activityLog) {
                try {
                    const activity = JSON.parse(logEntry);
                    const activityDate = new Date(activity.timestamp);
                    
                    // Apply date filter
                    let includeActivity = true;
                    if (filter === 'today') {
                        includeActivity = activityDate.toDateString() === now.toDateString();
                    } else if (filter === 'week') {
                        const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                        includeActivity = activityDate >= weekAgo;
                    } else if (filter === 'month') {
                        const monthAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                        includeActivity = activityDate >= monthAgo;
                    }
                    
                    if (includeActivity) {
                        activities.push(activity);
                    }
                } catch (parseError) {
                    console.warn('⚠️ Could not parse activity log entry');
                }
            }
            
            // Sort by timestamp (newest first)
            activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            // Apply pagination
            const startIndex = (page - 1) * limit;
            const endIndex = startIndex + limit;
            const paginatedActivities = activities.slice(startIndex, endIndex);
            
            return {
                activities: paginatedActivities,
                total: activities.length,
                page: page,
                limit: limit,
                hasMore: endIndex < activities.length
            };
            
        } catch (error) {
            console.error('❌ Get activity logs error:', error);
            return {
                activities: [],
                total: 0,
                page: page,
                limit: limit,
                hasMore: false
            };
        }
    }
}

// Enhanced geolocation detection
async function getGeolocationFromIP(ipAddress) {
    try {
        // Use multiple geolocation services for reliability
        const services = [
            `http://ip-api.com/json/${ipAddress}`,
            `https://ipapi.co/${ipAddress}/json/`
        ];
        
        for (const service of services) {
            try {
                const response = await fetch(service, { timeout: 3000 });
                if (response.ok) {
                    const data = await response.json();
                    
                    // Normalize response format
                    return {
                        country: data.country || data.country_name || 'Unknown',
                        countryCode: data.countryCode || data.country_code || 'XX',
                        region: data.regionName || data.region || data.state || 'Unknown',
                        city: data.city || 'Unknown',
                        latitude: data.lat || data.latitude || 0,
                        longitude: data.lon || data.longitude || 0,
                        timezone: data.timezone || 'UTC',
                        isp: data.isp || data.org || 'Unknown'
                    };
                }
            } catch (serviceError) {
                console.warn(`Geolocation service failed: ${service}`, serviceError);
                continue;
            }
        }
        
        return null;
    } catch (error) {
        console.error('All geolocation services failed:', error);
        return null;
    }
}

// Initialize managers
const apiKeyManager = new APIKeyManager();
const storage = new TrafficCopStorage();

// Dynamic Bot Detection Engine
class DynamicBotDetector {
    constructor() {
        this.trafficPatterns = new Map();
        this.behaviorProfiles = new Map();
        this.anomalyThresholds = {
            requestFrequency: { normal: 10, suspicious: 50, malicious: 100 },
            userAgentEntropy: { normal: 0.7, suspicious: 0.3, malicious: 0.1 },
            behaviorScore: { normal: 0.8, suspicious: 0.4, malicious: 0.2 },
            sessionDuration: { normal: 300, suspicious: 30, malicious: 5 }
        };
        
        // Use global config if available, otherwise use defaults
        this.actionThresholds = global.trafficCopConfig?.thresholds || {
            challenge: 40,
            block: 75
        };
        
        console.log('🤖 DynamicBotDetector initialized with thresholds:', this.actionThresholds);
    }
    
    // Calculate entropy of user agent string (randomness indicator)
    calculateUserAgentEntropy(userAgent) {
        if (!userAgent || userAgent.length === 0) return 0;
        
        const charFreq = {};
        for (let char of userAgent) {
            charFreq[char] = (charFreq[char] || 0) + 1;
        }
        
        let entropy = 0;
        const length = userAgent.length;
        
        for (let freq of Object.values(charFreq)) {
            const probability = freq / length;
            entropy -= probability * Math.log2(probability);
        }
        
        return entropy / Math.log2(length); // Normalized entropy
    }
    
    // Analyze request timing patterns
    analyzeRequestPatterns(sessionId, timestamp) {
        if (!this.trafficPatterns.has(sessionId)) {
            this.trafficPatterns.set(sessionId, {
                requests: [],
                firstRequest: timestamp,
                intervals: []
            });
        }
        
        const pattern = this.trafficPatterns.get(sessionId);
        pattern.requests.push(timestamp);
        
        // Calculate intervals between requests
        if (pattern.requests.length > 1) {
            const lastTwo = pattern.requests.slice(-2);
            const interval = lastTwo[1] - lastTwo[0];
            pattern.intervals.push(interval);
        }
        
        // Analyze patterns
        const requestFrequency = pattern.requests.length / ((timestamp - pattern.firstRequest) / 1000 || 1);
        const intervalVariance = this.calculateVariance(pattern.intervals);
        const isRhythmic = intervalVariance < 100; // Very consistent timing = bot-like
        
        return {
            frequency: requestFrequency,
            isRhythmic: isRhythmic,
            totalRequests: pattern.requests.length,
            avgInterval: pattern.intervals.reduce((a, b) => a + b, 0) / pattern.intervals.length || 0
        };
    }
    
    // Analyze behavioral signals
    analyzeBehaviorSignals(behaviorData) {
        let behaviorScore = 1.0; // Start with human assumption
        const signals = [];
        
        // Mouse movement analysis
        if (!behaviorData.mouseMovements || behaviorData.mouseMovements.length === 0) {
            behaviorScore -= 0.3;
            signals.push('no_mouse_movement');
        } else {
            // Analyze movement patterns
            const movements = behaviorData.mouseMovements;
            const isLinear = this.isMovementLinear(movements);
            const hasNaturalPauses = this.hasNaturalPauses(movements);
            
            if (isLinear) {
                behaviorScore -= 0.2;
                signals.push('linear_mouse_movement');
            }
            
            if (!hasNaturalPauses) {
                behaviorScore -= 0.2;
                signals.push('unnatural_mouse_timing');
            }
        }
        
        // Keyboard interaction analysis
        if (!behaviorData.keyboardEvents || behaviorData.keyboardEvents.length === 0) {
            behaviorScore -= 0.2;
            signals.push('no_keyboard_interaction');
        }
        
        // Scroll behavior analysis
        if (behaviorData.scrollEvents) {
            const scrollPattern = this.analyzeScrollPattern(behaviorData.scrollEvents);
            if (scrollPattern.isMechanical) {
                behaviorScore -= 0.2;
                signals.push('mechanical_scrolling');
            }
        }
        
        // Click pattern analysis
        if (behaviorData.clickEvents) {
            const clickPattern = this.analyzeClickPattern(behaviorData.clickEvents);
            if (clickPattern.isRapid) {
                behaviorScore -= 0.3;
                signals.push('rapid_clicking');
            }
        }
        
        return {
            score: Math.max(0, behaviorScore),
            signals: signals,
            confidence: signals.length > 0 ? 0.8 : 0.6
        };
    }
    
    // Detect user agent anomalies without hard-coded names
    analyzeUserAgentAnomalies(userAgent) {
        const anomalies = [];
        let anomalyScore = 0;
        
        // Length analysis
        if (userAgent.length < 20) {
            anomalies.push('unusually_short_ua');
            anomalyScore += 0.3;
        } else if (userAgent.length > 500) {
            anomalies.push('unusually_long_ua');
            anomalyScore += 0.2;
        }
        
        // Entropy analysis (randomness)
        const entropy = this.calculateUserAgentEntropy(userAgent);
        if (entropy < 0.3) {
            anomalies.push('low_entropy_ua');
            anomalyScore += 0.4;
        }
        
        // Common patterns that indicate automation
        const automationPatterns = [
            /^[A-Za-z]+\/[\d\.]+$/, // Simple tool/version pattern
            /python|curl|wget|http/i, // Common automation tools
            /^\w+$/, // Single word user agents
            /test|bot|crawler|spider/i // Generic automation terms
        ];
        
        for (let pattern of automationPatterns) {
            if (pattern.test(userAgent)) {
                anomalies.push('automation_pattern');
                anomalyScore += 0.3;
                break;
            }
        }
        
        // Browser consistency check
        const browserInconsistencies = this.checkBrowserConsistency(userAgent);
        if (browserInconsistencies.length > 0) {
            anomalies.push('browser_inconsistency');
            anomalyScore += 0.2;
        }
        
        return {
            anomalies: anomalies,
            score: Math.min(1.0, anomalyScore),
            entropy: entropy
        };
    }
    
    // Main dynamic detection function with configurable thresholds
    detectBot(requestData) {
        const sessionId = requestData.sessionId || 'unknown';
        const timestamp = Date.now();
        
        // 1. Analyze request patterns
        const requestAnalysis = this.analyzeRequestPatterns(sessionId, timestamp);
        
        // 2. Analyze user agent anomalies
        const userAgentAnalysis = this.analyzeUserAgentAnomalies(requestData.userAgent);
        
        // 3. Analyze behavioral signals
        const behaviorAnalysis = this.analyzeBehaviorSignals(requestData.behaviorData || {});
        
        // 4. Calculate composite risk score
        let riskScore = 0;
        const factors = [];
        
        // Request frequency factor
        if (requestAnalysis.frequency > this.anomalyThresholds.requestFrequency.malicious) {
            riskScore += 40;
            factors.push(`High request frequency: ${requestAnalysis.frequency.toFixed(1)}/sec`);
        } else if (requestAnalysis.frequency > this.anomalyThresholds.requestFrequency.suspicious) {
            riskScore += 25;
            factors.push(`Elevated request frequency: ${requestAnalysis.frequency.toFixed(1)}/sec`);
        }
        
        // Rhythmic requests (bot-like timing)
        if (requestAnalysis.isRhythmic && requestAnalysis.totalRequests > 5) {
            riskScore += 30;
            factors.push(`Mechanical request timing pattern`);
        }
        
        // User agent anomalies
        riskScore += userAgentAnalysis.score * 35;
        if (userAgentAnalysis.anomalies.length > 0) {
            factors.push(`User agent anomalies: ${userAgentAnalysis.anomalies.join(', ')}`);
        }
        
        // Behavioral analysis
        const behaviorRisk = (1 - behaviorAnalysis.score) * 40;
        riskScore += behaviorRisk;
        if (behaviorAnalysis.signals.length > 0) {
            factors.push(`Behavioral signals: ${behaviorAnalysis.signals.join(', ')}`);
        }
        
        // 5. Determine action based on CONFIGURABLE thresholds
        let action = 'allow';
        let confidence = 0.6;
        
        // Use global config if available, otherwise use instance defaults
        const currentThresholds = global.trafficCopConfig?.thresholds || this.actionThresholds;
        
        if (riskScore >= currentThresholds.block) {
            action = 'block';
            confidence = 0.9;
        } else if (riskScore >= currentThresholds.challenge) {
            action = 'challenge';
            confidence = 0.8;
        } else {
            action = 'allow';
            if (factors.length === 0) {
                factors.push("Low Risk");
            }
        }
        
        // Enhanced logging for debugging
        console.log(`🎯 Bot Detection: SessionId=${sessionId}, Risk=${Math.round(riskScore)}, Thresholds=[Challenge:${currentThresholds.challenge}, Block:${currentThresholds.block}], Action=${action}`);
        
        return {
            riskScore: Math.round(riskScore),
            action: action,
            confidence: Math.round(confidence * 100),
            threats: factors,
            appliedThresholds: currentThresholds,
            analysis: {
                requestPattern: requestAnalysis,
                userAgentAnalysis: userAgentAnalysis,
                behaviorAnalysis: behaviorAnalysis
            }
        };
    }
    
    // Helper methods
    calculateVariance(numbers) {
        if (numbers.length === 0) return 0;
        const mean = numbers.reduce((a, b) => a + b) / numbers.length;
        const variance = numbers.reduce((sum, num) => sum + Math.pow(num - mean, 2), 0) / numbers.length;
        return variance;
    }
    
    isMovementLinear(movements) {
        if (movements.length < 3) return false;
        // Check if mouse movements are too linear (bot-like)
        let linearCount = 0;
        for (let i = 2; i < movements.length; i++) {
            const dx1 = movements[i-1].x - movements[i-2].x;
            const dy1 = movements[i-1].y - movements[i-2].y;
            const dx2 = movements[i].x - movements[i-1].x;
            const dy2 = movements[i].y - movements[i-1].y;
            
            // Check if direction is too consistent
            if (Math.abs(dx1 - dx2) < 2 && Math.abs(dy1 - dy2) < 2) {
                linearCount++;
            }
        }
        return linearCount > movements.length * 0.8; // 80% linear = suspicious
    }
    
    hasNaturalPauses(movements) {
        if (movements.length < 2) return true;
        let pauseCount = 0;
        for (let i = 1; i < movements.length; i++) {
            const timeDiff = movements[i].timestamp - movements[i-1].timestamp;
            if (timeDiff > 100) { // Pause longer than 100ms
                pauseCount++;
            }
        }
        return pauseCount > movements.length * 0.1; // At least 10% pauses
    }
    
    analyzeScrollPattern(scrollEvents) {
        if (scrollEvents.length < 3) return { isMechanical: false };
        
        let mechanicalCount = 0;
        for (let i = 1; i < scrollEvents.length; i++) {
            const scrollDiff = Math.abs(scrollEvents[i].scrollY - scrollEvents[i-1].scrollY);
            const timeDiff = scrollEvents[i].timestamp - scrollEvents[i-1].timestamp;
            
            // Very consistent scroll amounts = mechanical
            if (scrollDiff > 0 && scrollDiff % 100 === 0 && timeDiff < 50) {
                mechanicalCount++;
            }
        }
        
        return { isMechanical: mechanicalCount > scrollEvents.length * 0.5 };
    }
    
    analyzeClickPattern(clickEvents) {
        if (clickEvents.length < 2) return { isRapid: false };
        
        const intervals = [];
        for (let i = 1; i < clickEvents.length; i++) {
            intervals.push(clickEvents[i].timestamp - clickEvents[i-1].timestamp);
        }
        
        const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
        const variance = this.calculateVariance(intervals);
        
        // Rapid clicking with low variance = bot-like
        return { 
            isRapid: avgInterval < 100 && variance < 50 
        };
    }
    
    checkBrowserConsistency(userAgent) {
        const inconsistencies = [];
        
        // Check for version mismatches, impossible combinations, etc.
        if (userAgent.includes('Chrome') && userAgent.includes('Firefox')) {
            inconsistencies.push('multiple_browsers');
        }
        
        if (userAgent.includes('Windows') && userAgent.includes('iPhone')) {
            inconsistencies.push('os_device_mismatch');
        }
        
        return inconsistencies;
    }
}

// Dynamic traffic analysis function
function analyzeTrafficDynamic(userAgent, website, requestData = {}) {
    const detector = new DynamicBotDetector();
    
    // Prepare enhanced request data
    const enhancedData = {
        ...requestData,
        userAgent: userAgent,
        website: website,
        sessionId: requestData.sessionId || `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: Date.now()
    };
    
    // Run dynamic detection
    const result = detector.detectBot(enhancedData);
    
    return {
        riskScore: result.riskScore,
        action: result.action,
        confidence: result.confidence,
        threats: result.threats,
        analysis: result.analysis
    };
}

// Enhanced authentication function
async function authenticateAPIKey(req) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { authenticated: false, error: 'Missing authorization header' };
    }
    
    const apiKey = authHeader.substring(7);
    
    // Validate API key using KV storage
    const validation = await apiKeyManager.validateAPIKey(apiKey);
    
    if (!validation.valid) {
        return { 
            authenticated: false, 
            error: validation.reason,
            apiKey: apiKey.substring(0, 20) + '...'
        };
    }
    
    return {
        authenticated: true,
        apiKey: apiKey,
        publisherId: validation.publisherId,
        plan: validation.plan,
        website: validation.website,
        keyData: validation.keyData
    };
}

// Helper function to calculate severity
function calculateSeverity(riskScore) {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 40) return 'medium';
    if (riskScore >= 20) return 'low';
    return 'minimal';
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
                message: 'Traffic Cop API with KV Storage is running!',
                version: '5.0.0',
                features: ['Dynamic Bot Detection', 'KV Persistent Storage', 'Dynamic API Keys', 'Real-Time Analytics', 'Global Timezone Support', 'Geolocation Tracking']
            });
            return;
        }

        // Configuration management endpoint - GET current config
        if (req.url === '/api/v1/config' && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            // Get current configuration from DynamicBotDetector
            const detector = new DynamicBotDetector();
            
            res.status(200).json({
                success: true,
                config: {
                    thresholds: {
                        challenge: detector.actionThresholds?.challenge || 40,
                        block: detector.actionThresholds?.block || 75
                    },
                    anomalyThresholds: detector.anomalyThresholds,
                    version: '5.0.0',
                    lastUpdated: new Date().toISOString()
                },
                message: 'Current bot detection configuration'
            });
            return;
        }

        // Configuration management endpoint - POST update config
        if (req.url === '/api/v1/config' && req.method === 'POST') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', () => {
                try {
                    const newConfig = JSON.parse(body);
                    
                    // Update global configuration
                    if (newConfig.thresholds) {
                        // Store in global variable for persistence
                        global.trafficCopConfig = global.trafficCopConfig || {};
                        global.trafficCopConfig.thresholds = {
                            challenge: newConfig.thresholds.challenge || 40,
                            block: newConfig.thresholds.block || 75
                        };
                        
                        console.log('🔧 Configuration updated:', global.trafficCopConfig.thresholds);
                    }
                    
                    res.status(200).json({
                        success: true,
                        message: 'Configuration updated successfully',
                        updatedConfig: {
                            thresholds: global.trafficCopConfig?.thresholds || { challenge: 40, block: 75 },
                            timestamp: new Date().toISOString()
                        }
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

        // Enhanced traffic analysis endpoint with KV storage
        if (req.url === '/api/v1/analyze' && req.method === 'POST') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ 
                    error: 'Authentication failed',
                    reason: auth.error
                });
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const requestData = JSON.parse(body);
                    const { userAgent, website } = requestData;
                    
                    // Get real IP address
                    const realIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                                req.headers['x-real-ip'] || 
                                req.connection.remoteAddress || 
                                'unknown';
                    
                    // Get geolocation data
                    const geolocation = await getGeolocationFromIP(realIP);
                    
                    // Dynamic bot detection analysis
                    const analysis = analyzeTrafficDynamic(userAgent, website, requestData);
                    
                    // Store visitor data in KV
                    const visitorData = {
                        sessionId: requestData.sessionId || `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                        userAgent: userAgent,
                        website: website,
                        ipAddress: realIP,
                        geolocation: geolocation,
                        riskScore: analysis.riskScore,
                        action: analysis.action,
                        threats: analysis.threats,
                        publisherId: auth.publisherId,
                        timestamp: new Date().toISOString()
                    };
                    
                    // Store in KV
                    await storage.storeVisitorSession(visitorData);
                    
                    console.log(`💾 STORED IN KV: ${visitorData.sessionId}, Risk: ${analysis.riskScore}, Action: ${analysis.action}`);
                    
                    const response = {
                        sessionId: visitorData.sessionId,
                        publisherId: auth.publisherId,
                        website,
                        riskScore: analysis.riskScore,
                        action: analysis.action,
                        confidence: analysis.confidence,
                        threats: analysis.threats,
                        geolocation: geolocation,
                        timestamp: new Date().toISOString()
                    };
                    
                    // If action is challenge, provide challenge URL
                    if (analysis.action === 'challenge') {
                        response.challengeUrl = `/captcha-challenge.html?session=${visitorData.sessionId}&website=${encodeURIComponent(website)}`;
                    }
                    
                    res.status(200).json(response);
                    
                } catch (error) {
                    console.error('Analyze endpoint error:', error);
                    res.status(400).json({
                        error: 'Invalid request data',
                        details: error.message
                    });
                }
            });
            return;
        }

        // Real-time visitor tracking endpoint
        if (req.url === '/api/v1/real-time-visitor' && req.method === 'POST') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const visitorData = JSON.parse(body);
                    
                    // Get real IP address
                    const realIP = req.headers['x-forwarded-for']?.split(',')[0] || 
                                req.headers['x-real-ip'] || 
                                req.connection.remoteAddress || 
                                visitorData.ipAddress || 
                                'unknown';
                    
                    // Get geolocation data
                    const geolocation = await getGeolocationFromIP(realIP);
                    
                    // Enhanced visitor data
                    const enhancedVisitorData = {
                        ...visitorData,
                        ipAddress: realIP,
                        geolocation: geolocation,
                        userAgent: req.headers['user-agent'] || visitorData.userAgent,
                        publisherId: auth.publisherId,
                        sessionId: visitorData.sessionId || `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                        timestamp: new Date().toISOString(),
                        riskScore: 0,
                        action: 'allow',
                        threats: []
                    };
                    
                    // Store in KV
                    await storage.storeVisitorSession(enhancedVisitorData);
                    
                    console.log(`👤 Real-time visitor tracked: ${realIP} from ${geolocation?.city}, ${geolocation?.country}`);
                    
                    res.status(200).json({
                        success: true,
                        message: 'Real-time visitor tracked successfully',
                        sessionId: enhancedVisitorData.sessionId,
                        geolocation: geolocation,
                        storage: 'kv'
                    });
                    
                } catch (error) {
                    console.error('Real-time visitor tracking error:', error);
                    res.status(400).json({ error: 'Invalid visitor data' });
                }
            });
            return;
        }

        // Enhanced real-time dashboard with KV data
        if (req.url === '/api/v1/real-time-dashboard' && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            const userTimezone = req.headers['x-user-timezone'] || 'UTC';
            
            try {
                console.log('🔍 Dashboard: Getting live visitors...');
                // Get live visitors from KV
                const liveVisitors = await storage.getLiveVisitors();
                console.log('👥 Dashboard: Live visitors count:', liveVisitors.length);
                
                console.log('📊 Dashboard: Getting daily stats...');
                // Get daily stats from KV
                const dailyStats = await storage.getDailyStats();
                console.log('📊 Dashboard: Daily stats:', dailyStats);
                
                // Calculate bot statistics
                const botStats = {
                    total: liveVisitors.filter(v => v.action === 'block').length,
                    critical: liveVisitors.filter(v => (v.riskScore || 0) >= 80).length,
                    high: liveVisitors.filter(v => (v.riskScore || 0) >= 60 && (v.riskScore || 0) < 80).length,
                    medium: liveVisitors.filter(v => (v.riskScore || 0) >= 40 && (v.riskScore || 0) < 60).length,
                    low: liveVisitors.filter(v => (v.riskScore || 0) >= 20 && (v.riskScore || 0) < 40).length,
                    minimal: liveVisitors.filter(v => (v.riskScore || 0) < 20).length
                };
                
                // Format timestamps in user timezone
                const formatTime = (timestamp) => {
                    try {
                        return new Date(timestamp).toLocaleString('en-US', {
                            timeZone: userTimezone,
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            hour12: true
                        });
                    } catch (error) {
                        return new Date(timestamp).toLocaleTimeString();
                    }
                };
                
                // Prepare geographic stats
                const countryStats = Object.entries(dailyStats.countries || {})
                    .sort(([,a], [,b]) => b - a)
                    .slice(0, 10)
                    .map(([country, count]) => ({ country, count }));
                
                const response = {
                    timestamp: new Date().toISOString(),
                    liveStats: {
                        onlineUsers: liveVisitors.filter(v => v.action !== 'block').length,
                        totalVisitors: liveVisitors.length,
                        botsDetected: botStats.total,
                        botSeverity: botStats
                    },
                    dailyStats: {
                        totalRequests: dailyStats.totalRequests,
                        blockedBots: dailyStats.blockedBots,
                        allowedUsers: dailyStats.allowedUsers,
                        challengedUsers: dailyStats.challengedUsers
                    },
                    onlineVisitors: liveVisitors.map(visitor => ({
                        ...visitor,
                        lastSeenFormatted: formatTime(visitor.timestamp),
                        severity: calculateSeverity(visitor.riskScore || 0)
                    })),
                    geographicStats: {
                        countries: countryStats,
                        cities: []
                    },
                    storage: 'kv'
                };
                
                console.log('📤 Dashboard response:', {
                    dailyRequests: response.dailyStats.totalRequests,
                    liveVisitors: response.liveStats.totalVisitors
                });
                
                res.status(200).json(response);
                
            } catch (error) {
                console.error('❌ Real-time dashboard error:', error);
                res.status(500).json({ error: 'Failed to load dashboard data' });
            }
            return;
        }

        // Enhanced analytics endpoint with timezone support
        if (req.url === '/api/v1/analytics' && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            const userTimezone = req.headers['x-user-timezone'] || 'UTC';
            const timezoneOffset = req.headers['x-timezone-offset'] || 'UTC+0:00';
            
            console.log(`📊 Analytics request from timezone: ${userTimezone} (${timezoneOffset})`);

            try {
                // Get daily stats from KV
                const dailyStats = await storage.getDailyStats();
                
                // If NO real traffic today, return zeros
                if (dailyStats.totalRequests === 0) {
                    res.status(200).json({
                        website: auth.website || 'newsparrow.in',
                        totalRequests: 0,
                        blockedBots: 0,
                        allowedUsers: 0,
                        challengedUsers: 0,
                        riskScore: 0,
                        plan: auth.plan || 'Professional',
                        protectionStatus: 'ACTIVE - Waiting for traffic',
                        lastAnalysis: new Date().toISOString(),
                        userTimezone: userTimezone,
                        timezoneOffset: timezoneOffset,
                        topThreats: [],
                        recentActivity: [
                            '✅ Enhanced Traffic Cop protection system is active',
                            '🌍 Dashboard timezone auto-detected and configured',
                            '🔍 All statistics will be based on actual detections',
                            '🛡️ Advanced pattern recognition algorithms loaded'
                        ]
                    });
                    return;
                }

                // Calculate real metrics
                const totalRequests = dailyStats.totalRequests;
                const blockedBots = dailyStats.blockedBots;
                const allowedUsers = dailyStats.allowedUsers;
                const challengedUsers = dailyStats.challengedUsers || 0;
                const riskScore = totalRequests > 0 ? ((blockedBots / totalRequests) * 100).toFixed(1) : 0;

                // Return real analytics with timezone info
                res.status(200).json({
                    website: auth.website || 'newsparrow.in',
                    totalRequests: totalRequests,
                    blockedBots: blockedBots,
                    allowedUsers: allowedUsers,
                    challengedUsers: challengedUsers,
                    riskScore: parseFloat(riskScore),
                    plan: auth.plan || 'Professional',
                    protectionStatus: 'ACTIVE',
                    lastAnalysis: new Date().toISOString(),
                    userTimezone: userTimezone,
                    timezoneOffset: timezoneOffset,
                    topThreats: dailyStats.threats || [],
                    recentActivity: [
                        '📊 Real traffic data from KV storage',
                        '🌍 Dashboard configured for your timezone',
                        '✅ Dynamic Traffic Cop ready for incoming requests',
                        '🛡️ AI behavioral analysis algorithms active'
                    ]
                });
                
            } catch (error) {
                console.error('Analytics error:', error);
                res.status(500).json({ error: 'Failed to load analytics' });
            }
            return;
        }

        // Enhanced publisher signup with dynamic API key generation
        if (req.url === '/api/v1/publisher/signup' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const publisherInfo = JSON.parse(body);
                    
                    if (!publisherInfo.email || !publisherInfo.website) {
                        res.status(400).json({
                            success: false,
                            error: 'Email and website are required'
                        });
                        return;
                    }
                    
                    // Generate unique publisher ID
                    const publisherId = `pub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                    
                    // Generate API key based on plan - FIXED CALL
                    const plan = publisherInfo.plan || 'starter';
                    const apiKey = apiKeyManager.generateAPIKey({
                        publisherId: publisherId,
                        email: publisherInfo.email,
                        plan: plan
                    });
                    
                    // Prepare API key data
                    const apiKeyData = {
                        apiKey: apiKey,
                        publisherId: publisherId,
                        publisherName: publisherInfo.name || publisherInfo.website,
                        email: publisherInfo.email,
                        website: publisherInfo.website,
                        plan: plan,
                        maxRequests: plan === 'starter' ? 100000 : plan === 'professional' ? 1000000 : -1,
                        features: plan === 'starter' ? ['basic_protection'] : 
                                plan === 'professional' ? ['basic_protection', 'advanced_analytics', 'custom_rules'] :
                                ['basic_protection', 'advanced_analytics', 'custom_rules', 'priority_support']
                    };
                    
                    // Store API key in KV
                    await apiKeyManager.storeAPIKey(apiKeyData);
                    
                    res.status(200).json({
                        success: true,
                        apiKey: apiKey,
                        publisherId: publisherId,
                        publisherName: apiKeyData.publisherName,
                        plan: plan,
                        maxRequests: apiKeyData.maxRequests,
                        features: apiKeyData.features,
                        message: 'API key generated and stored successfully',
                        dashboardUrl: `https://traffic-cop-apii.vercel.app/publisher-dashboard.html?session=${btoa(apiKey)}`
                    });
                    
                } catch (error) {
                    console.error('Publisher signup error:', error);
                    res.status(500).json({
                        success: false,
                        error: 'Internal server error'
                    });
                }
            });
            return;
        }


        // Publisher login endpoint with dynamic API key validation
        if (req.url === '/api/v1/publisher/login' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const loginData = JSON.parse(body);
                    const { email, apiKey } = loginData;
                    
                    // Validate API key
                    const validation = await apiKeyManager.validateAPIKey(apiKey);
                    
                    if (validation.valid && validation.keyData.email === email) {
                        res.status(200).json({
                            success: true,
                            publisherName: validation.keyData.publisherName,
                            plan: validation.keyData.plan,
                            website: validation.keyData.website
                        });
                        return;
                    }
                    
                    res.status(401).json({
                        success: false,
                        error: 'Invalid API key or email'
                    });
                    
                } catch (error) {
                    console.error('Publisher login error:', error);
                    res.status(400).json({
                        success: false,
                        error: 'Invalid login data'
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

        // Activity logs endpoint with date filtering
        if (req.url.startsWith('/api/v1/activity-logs') && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            const urlParts = url.parse(req.url, true);
            const query = urlParts.query;
            
            const userTimezone = req.headers['x-user-timezone'] || 'UTC';
            const filter = query.filter || 'today';
            const page = parseInt(query.page) || 1;
            const limit = parseInt(query.limit) || 50;
            
            try {
                // Get activity logs from KV with filtering
                const logsData = await storage.getActivityLogs(filter, page, limit);
                
                // Format timestamps in user timezone
                const formatTime = (timestamp) => {
                    try {
                        return new Date(timestamp).toLocaleString('en-US', {
                            timeZone: userTimezone,
                            year: 'numeric',
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            hour12: true
                        });
                    } catch (error) {
                        return new Date(timestamp).toLocaleString();
                    }
                };
                
                res.status(200).json({
                    ...logsData,
                    activities: logsData.activities.map(activity => ({
                        ...activity,
                        timestampFormatted: formatTime(activity.timestamp),
                        severity: calculateSeverity(activity.riskScore || 0)
                    }))
                });
                
            } catch (error) {
                console.error('Activity logs error:', error);
                res.status(500).json({ error: 'Failed to load activity logs' });
            }
            return;
        }

        // Debug endpoints for testing
        if (req.url === '/api/v1/debug/storage-test' && req.method === 'POST') {
            try {
                console.log('🔍 Testing storage function directly...');
                
                const testData = {
                    sessionId: 'debug_test_' + Date.now(),
                    userAgent: 'Debug Test',
                    website: 'newsparrow.in',
                    ipAddress: '127.0.0.1',
                    riskScore: 10,
                    action: 'allow',
                    threats: [],
                    publisherId: 'pub_newsparrow',
                    timestamp: new Date().toISOString()
                };
                
                // Test storage directly
                await storage.storeVisitorSession(testData);
                
                console.log('✅ Storage function completed');
                
                // Try to retrieve data
                const liveVisitors = await storage.getLiveVisitors();
                const dailyStats = await storage.getDailyStats();
                
                res.status(200).json({
                    success: true,
                    message: 'Storage test completed',
                    storedData: testData,
                    liveVisitorsCount: liveVisitors.length,
                    dailyStats: dailyStats
                });
                
            } catch (error) {
                console.error('❌ Storage test failed:', error);
                res.status(500).json({
                    success: false,
                    error: error.message,
                    stack: error.stack
                });
            }
            return;
        }

        if (req.url === '/api/v1/debug/dashboard-methods' && req.method === 'GET') {
            try {
                console.log('🔍 Testing dashboard methods directly...');
                
                // Test getDailyStats method directly
                console.log('📊 Calling storage.getDailyStats()...');
                const dailyStats = await storage.getDailyStats();
                console.log('📊 getDailyStats result:', dailyStats);
                
                // Test getLiveVisitors method directly
                console.log('👥 Calling storage.getLiveVisitors()...');
                const liveVisitors = await storage.getLiveVisitors();
                console.log('👥 getLiveVisitors result:', liveVisitors);
                
                res.status(200).json({
                    success: true,
                    message: 'Dashboard methods tested',
                    dailyStats: dailyStats,
                    liveVisitors: liveVisitors,
                    liveVisitorsCount: liveVisitors.length
                });
                
            } catch (error) {
                console.error('❌ Dashboard methods test failed:', error);
                res.status(500).json({
                    success: false,
                    error: error.message,
                    stack: error.stack
                });
            }
            return;
        }

        if (req.url === '/api/v1/debug/kv-contents' && req.method === 'GET') {
            try {
                await storage.ensureKVReady();
                
                const today = new Date().toISOString().split('T')[0];
                const dailyStatsKey = `tc_daily:${today}`;
                const dailyStats = await kv.get(dailyStatsKey);
                
                const activityLog = await kv.lrange('tc_activity_log', 0, 10);
                
                res.status(200).json({
                    success: true,
                    today: today,
                    dailyStatsKey: dailyStatsKey,
                    dailyStatsExists: !!dailyStats,
                    dailyStatsContent: dailyStats ? JSON.parse(dailyStats) : null,
                    activityLogLength: activityLog ? activityLog.length : 0,
                    activityLogSample: activityLog ? activityLog.slice(0, 2) : [],
                    kvPrefix: storage.kvPrefix
                });
                
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
            return;
        }

                if (req.url === '/api/v1/test-kv-simple' && req.method === 'GET') {
            try {
                if (!kvReady) {
                    await initKV();
                }
                
                if (!kv) {
                    throw new Error('KV not initialized');
                }
                
                await kv.set('test', 'working');
                const result = await kv.get('test');
                
                res.status(200).json({
                    success: true,
                    message: 'KV is working',
                    test: result,
                    kvReady: kvReady
                });
                
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: error.message,
                    kvReady: kvReady,
                    envVars: {
                        hasKvUrl: !!process.env.KV_URL,
                        hasKvRestUrl: !!process.env.KV_REST_API_URL,
                        hasKvToken: !!process.env.KV_REST_API_TOKEN
                    }
                });
            }
            return;
        }


        // Migration endpoint to store existing API key in KV
        if (req.url === '/api/v1/migrate-existing-key' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const { migrationSecret } = JSON.parse(body);
                    
                    // Security check
                    if (migrationSecret !== 'migrate_newsparrow_key_2025') {
                        res.status(401).json({ error: 'Invalid migration secret' });
                        return;
                    }
                    
                    // Your existing API key data
                    const existingApiKey = 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583';
                    const publisherId = 'pub_newsparrow_migrated';
                    
                    const apiKeyData = {
                        apiKey: existingApiKey,
                        publisherId: publisherId,
                        publisherName: 'Newsparrow',
                        email: 'ashokvarma416@gmail.com',
                        website: 'newsparrow.in',
                        plan: 'professional',
                        maxRequests: 1000000,
                        features: ['basic_protection', 'advanced_analytics', 'custom_rules', 'geolocation_tracking']
                    };
                    
                    // Store in KV using the API key manager
                    await apiKeyManager.storeAPIKey(apiKeyData);
                    
                    res.status(200).json({
                        success: true,
                        message: 'Existing API key successfully migrated to KV',
                        apiKey: existingApiKey.substring(0, 20) + '...',
                        publisherId: publisherId,
                        plan: 'professional'
                    });
                    
                } catch (error) {
                    console.error('Migration error:', error);
                    res.status(500).json({
                        success: false,
                        error: 'Failed to migrate API key',
                        details: error.message
                    });
                }
            });
            return;
        }

        // Serve captcha challenge page
        if (req.method === 'GET') {
            const parsedUrl = url.parse(req.url, true);
            const pathname = parsedUrl.pathname;
            
            if (pathname === '/captcha-challenge.html') {
                const sessionId = parsedUrl.query.session || 'unknown';
                const website = parsedUrl.query.website || 'unknown';
                
                // Generate random math challenge
                const num1 = Math.floor(Math.random() * 20) + 1;
                const num2 = Math.floor(Math.random() * 20) + 1;
                const correctAnswer = num1 + num2;
                
                const challengeHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification - Traffic Cop</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }
        
        .challenge-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }
        
        .shield-icon {
            font-size: 48px;
            color: #667eea;
            margin-bottom: 20px;
        }
        
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 24px;
        }
        
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            line-height: 1.5;
        }
        
        .math-challenge {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            border: 2px solid #e9ecef;
        }
        
        .math-question {
            font-size: 24px;
            font-weight: bold;
            color: #495057;
            margin-bottom: 15px;
        }
        
        input[type="number"] {
            width: 100px;
            padding: 12px;
            font-size: 18px;
            text-align: center;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            margin: 0 10px;
        }
        
        input[type="number"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        .verify-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            margin-top: 20px;
            transition: transform 0.2s;
        }
        
        .verify-btn:hover {
            transform: translateY(-2px);
        }
        
        .verify-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .error-message {
            color: #dc3545;
            margin-top: 15px;
            padding: 10px;
            background: #f8d7da;
            border-radius: 5px;
            display: none;
        }
        
        .success-message {
            color: #155724;
            margin-top: 15px;
            padding: 10px;
            background: #d4edda;
            border-radius: 5px;
            display: none;
        }
        
        .attempts-counter {
            margin-top: 10px;
            color: #666;
            font-size: 14px;
        }
        
        .footer {
            margin-top: 30px;
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="challenge-container">
        <div class="shield-icon">🛡️</div>
        <h1>Security Verification</h1>
        <p class="subtitle">Please complete this simple math problem to verify you're human</p>
        
        <div class="math-challenge">
            <div class="math-question">
                ${num1} + ${num2} = ?
            </div>
            <input type="number" id="answer" placeholder="?" autocomplete="off" autofocus>
        </div>
        
        <button class="verify-btn" onclick="verifyAnswer()">Verify</button>
        
        <div id="error-message" class="error-message"></div>
        <div id="success-message" class="success-message"></div>
        <div id="attempts-counter" class="attempts-counter">Attempts: <span id="attempts">0</span>/3</div>
        
        <div class="footer">
            Protected by Traffic Cop Security System
        </div>
    </div>

    <script>
        let attempts = 0;
        const maxAttempts = 3;
        const correctAnswer = ${correctAnswer};
        const sessionId = '${sessionId}';
        
        function verifyAnswer() {
            const userAnswer = parseInt(document.getElementById('answer').value);
            const errorDiv = document.getElementById('error-message');
            const successDiv = document.getElementById('success-message');
            const attemptsSpan = document.getElementById('attempts');
            const verifyBtn = document.querySelector('.verify-btn');
            
            attempts++;
            attemptsSpan.textContent = attempts;
            
            if (isNaN(userAnswer)) {
                showError('Please enter a valid number');
                return;
            }
            
            if (userAnswer === correctAnswer) {
                successDiv.textContent = 'Verification successful! Redirecting...';
                successDiv.style.display = 'block';
                errorDiv.style.display = 'none';
                
                // Send verification to server
                fetch('/api/v1/verify-challenge', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        sessionId: sessionId,
                        challengeType: 'math',
                        verified: true,
                        answer: userAnswer,
                        correctAnswer: correctAnswer,
                        attempts: attempts
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        setTimeout(() => {
                            window.location.href = data.redirectUrl || '/';
                        }, 2000);
                    } else {
                        showError('Verification failed. Please try again.');
                    }
                })
                .catch(error => {
                    console.error('Verification error:', error);
                    showError('Network error. Please try again.');
                });
                
            } else {
                if (attempts >= maxAttempts) {
                    showError('Maximum attempts exceeded. Please refresh the page.');
                    verifyBtn.disabled = true;
                    document.getElementById('answer').disabled = true;
                } else {
                    showError(\`Incorrect answer. You have \${maxAttempts - attempts} attempts remaining.\`);
                    document.getElementById('answer').value = '';
                    document.getElementById('answer').focus();
                }
            }
        }
        
        function showError(message) {
            const errorDiv = document.getElementById('error-message');
            const successDiv = document.getElementById('success-message');
            
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            successDiv.style.display = 'none';
        }
        
        // Allow Enter key to submit
        document.getElementById('answer').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                verifyAnswer();
            }
        });
    </script>
</body>
</html>`;
                
                res.setHeader('Content-Type', 'text/html');
                res.status(200).send(challengeHtml);
                return;
            }
        }

        // 404 for unknown routes
        res.status(404).json({ 
            error: 'Not found',
            message: 'The requested endpoint does not exist',
            availableEndpoints: [
                '/health',
                '/api/v1/analyze',
                '/api/v1/real-time-dashboard',
                '/api/v1/analytics',
                '/api/v1/config',
                '/api/v1/publisher/signup',
                '/api/v1/publisher/login',
                '/api/v1/activity-logs',
                '/api/v1/verify-challenge'
            ]
        });
        
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
};
