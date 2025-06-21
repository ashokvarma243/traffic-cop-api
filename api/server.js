// server.js - Enhanced Traffic Cop API Server with KV Storage and Dynamic API Keys
const url = require('url');

// Dynamic import for KV (since it's ES6 module)
let kv;
let kvInitialized = false;
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

// Fallback in-memory storage (when KV is not available)
let realTrafficData = {
    dailyStats: new Map(),
    detectionHistory: []
};
let realTimeVisitors = new Map();
let visitorHistory = [];

// API Key Management with KV Storage
class APIKeyManager {
    constructor() {
        this.kvPrefix = 'tc_api_';
    }
    
    async ensureKVReady() {
        if (!kvInitialized) {
            await initializeKV();
        }
        if (!kv) {
            throw new Error('KV module not available');
        }
        return true;
    }
    
    // Generate new API key
    generateAPIKey(publisherId, plan = 'starter') {
        const timestamp = Date.now();
        const randomPart = Math.random().toString(36).substr(2, 32);
        const planPrefix = plan.substring(0, 4);
        return `tc_${planPrefix}_${timestamp}_${randomPart}`;
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
                status: 'active'
            };
            
            // Store API key data
            await kv.set(`${this.kvPrefix}key:${apiKeyData.apiKey}`, JSON.stringify(keyData));
            
            // Store publisher mapping
            await kv.set(`${this.kvPrefix}publisher:${apiKeyData.publisherId}`, apiKeyData.apiKey);
            
            // Add to active keys list
            await kv.sadd(`${this.kvPrefix}active_keys`, apiKeyData.apiKey);
            
            console.log(`🔑 API key stored: ${apiKeyData.apiKey.substring(0, 20)}...`);
            
            return keyData;
            
        } catch (error) {
            console.error('API key storage error:', error);
            throw error;
        }
    }
    
    // Validate API key
    async validateAPIKey(apiKey) {
        try {
            await this.ensureKVReady();
            
            const keyDataStr = await kv.get(`${this.kvPrefix}key:${apiKey}`);
            if (!keyDataStr) {
                return { valid: false, reason: 'API key not found' };
            }
            
            const keyData = JSON.parse(keyDataStr);
            
            // Check if key is active
            if (keyData.status !== 'active') {
                return { valid: false, reason: 'API key is inactive' };
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
                website: keyData.website
            };
            
        } catch (error) {
            console.error('API key validation error:', error);
            // Fallback to hardcoded key for existing users
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
}

// KV Storage Helper Functions
class TrafficCopStorage {
    constructor() {
        this.kvPrefix = 'tc_';
    }
    
    async ensureKVReady() {
        if (!kv) {
            const kvModule = await import('@vercel/kv');
            kv = kvModule.kv;
        }
    }
    
    // Enhanced storeVisitorSession with detailed logging
    async storeVisitorSession(visitorData) {
        try {
            console.log('🔄 Starting storeVisitorSession for:', visitorData.sessionId);
            
            await this.ensureKVReady();
            console.log('✅ KV ready check passed');
            
            const sessionKey = `${this.kvPrefix}session:${visitorData.sessionId}`;
            const sessionData = {
                ...visitorData,
                timestamp: new Date().toISOString(),
                expiresAt: Date.now() + (30 * 60 * 1000)
            };
            
            console.log('🔄 Attempting to store in KV with key:', sessionKey);
            
            // Store session with 30-minute expiry
            await kv.setex(sessionKey, 1800, JSON.stringify(sessionData));
            console.log('✅ Session stored in KV successfully');
            
            // Add to activity log
            console.log('🔄 Adding to activity log...');
            await this.addToActivityLog(visitorData);
            console.log('✅ Activity log updated');
            
            // Update daily stats
            console.log('🔄 Updating daily stats...');
            await this.updateDailyStats(visitorData);
            console.log('✅ Daily stats updated');
            
            console.log(`💾 COMPLETED storing visitor session: ${visitorData.sessionId}`);
            
        } catch (error) {
            console.error('❌ KV storage error in storeVisitorSession:', error);
            throw error; // Re-throw to see the error in debug
        }
    }

    
    // Add to activity log
    async addToActivityLog(visitorData) {
        try {
            await this.ensureKVReady();
            
            const logEntry = {
                ...visitorData,
                timestamp: new Date().toISOString(),
                id: `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
            };
            
            console.log('🔄 Adding to activity log with key: tc_activity_log');
            await kv.lpush(`${this.kvPrefix}activity_log`, JSON.stringify(logEntry));
            await kv.ltrim(`${this.kvPrefix}activity_log`, 0, 9999);
            console.log('✅ Activity log entry added');
            
        } catch (error) {
            console.error('❌ Activity log error:', error);
            throw error;
        }
    }

    async updateDailyStats(visitorData) {
    try {
        await this.ensureKVReady();
        
        const today = new Date().toISOString().split('T')[0];
        const statsKey = `${this.kvPrefix}daily:${today}`;
        
        console.log('🔄 Updating daily stats for key:', statsKey);
        
        // Get current stats with better error handling
        let currentStats;
        try {
            const currentStatsStr = await kv.get(statsKey);
            console.log('📊 Raw KV data:', currentStatsStr);
            
            if (currentStatsStr && currentStatsStr !== 'null' && currentStatsStr !== 'undefined') {
                // Only parse if we have valid data
                currentStats = JSON.parse(currentStatsStr);
                console.log('✅ Parsed existing stats:', currentStats);
            } else {
                console.log('📊 No existing stats, creating new');
                currentStats = null;
            }
        } catch (parseError) {
            console.error('❌ JSON parse error, creating fresh stats:', parseError);
            currentStats = null;
        }
        
        // Create fresh stats if parsing failed or no data exists
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
            console.log('📊 Created fresh stats object');
        }
        
        // Update counters
        currentStats.totalRequests++;
        console.log('📊 Total requests now:', currentStats.totalRequests);
        
        if (visitorData.action === 'block') {
            currentStats.blockedBots++;
        } else if (visitorData.action === 'challenge') {
            currentStats.challengedUsers++;
        } else {
            currentStats.allowedUsers++;
        }
        
        // Update geographic data safely
        if (visitorData.geolocation) {
            const country = visitorData.geolocation.country || 'Unknown';
            const city = visitorData.geolocation.city || 'Unknown';
            
            currentStats.countries[country] = (currentStats.countries[country] || 0) + 1;
            currentStats.cities[city] = (currentStats.cities[city] || 0) + 1;
        }
        
        // Store updated stats with error handling
        try {
            const statsToStore = JSON.stringify(currentStats);
            await kv.setex(statsKey, 604800, statsToStore);
            console.log('✅ Daily stats updated and stored successfully');
        } catch (storeError) {
            console.error('❌ Failed to store stats:', storeError);
            throw storeError;
        }
        
    } catch (error) {
        console.error('❌ Daily stats error:', error);
        throw error;
    }
}


    
    // Get live visitor sessions
    async getLiveVisitors() {
        try {
            await this.ensureKVReady();
            
            const pattern = `${this.kvPrefix}session:*`;
            const sessionKeys = await kv.keys(pattern);
            
            const sessions = [];
            for (const key of sessionKeys) {
                const sessionDataStr = await kv.get(key);
                if (sessionDataStr) {
                    const session = JSON.parse(sessionDataStr);
                    
                    // Check if session is still active (last 5 minutes)
                    const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
                    if (session.timestamp && new Date(session.timestamp).getTime() > fiveMinutesAgo) {
                        sessions.push(session);
                    }
                }
            }
            
            return sessions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
        } catch (error) {
            console.error('Get live visitors error:', error);
            return [];
        }
    }
    
    // Get daily statistics
    async getDailyStats(date = null) {
        try {
            await this.ensureKVReady();
            
            const targetDate = date || new Date().toISOString().split('T')[0];
            const statsKey = `${this.kvPrefix}daily:${targetDate}`;
            
            const statsStr = await kv.get(statsKey);
            return statsStr ? JSON.parse(statsStr) : {
                date: targetDate,
                totalRequests: 0,
                blockedBots: 0,
                allowedUsers: 0,
                challengedUsers: 0,
                threats: [],
                countries: {},
                cities: {}
            };
            
        } catch (error) {
            console.error('Get daily stats error:', error);
            return this.getFallbackStats();
        }
    }
    
    // Fallback in-memory storage
    fallbackStorage(visitorData) {
        console.log('📝 Using fallback in-memory storage');
        recordRealTrafficEvent(
            visitorData.action === 'block',
            visitorData.riskScore,
            visitorData.threats,
            visitorData.userAgent,
            visitorData.website,
            visitorData.action
        );
    }
    
    // Get fallback stats from in-memory storage
    getFallbackStats() {
        const today = getTodayKey();
        const todayStats = realTrafficData.dailyStats.get(today);
        
        if (!todayStats) {
            return {
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
        
        return {
            date: today,
            totalRequests: todayStats.totalRequests,
            blockedBots: todayStats.blockedBots,
            allowedUsers: todayStats.allowedUsers,
            challengedUsers: todayStats.challengedUsers,
            threats: Array.from(todayStats.threats),
            countries: {},
            cities: {}
        };
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

// Dynamic Bot Detection Engine - No Hard-Coded Names
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
        
        // Store learning data for model improvement
        this.updateLearningData(sessionId, {
            riskScore,
            factors,
            userAgentEntropy: userAgentAnalysis.entropy,
            behaviorScore: behaviorAnalysis.score,
            requestPattern: requestAnalysis,
            appliedThresholds: currentThresholds
        });
        
        return {
            riskScore: Math.round(riskScore),
            action: action,
            confidence: Math.round(confidence * 100),
            threats: factors,
            appliedThresholds: currentThresholds, // Include current thresholds in response
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
    
    updateLearningData(sessionId, analysisData) {
        // Store data for machine learning model improvement
        console.log(`Learning data updated for session ${sessionId}: Risk ${analysisData.riskScore}`);
    }
}

// Function to get today's key for daily statistics
function getTodayKey() {
    return new Date().toISOString().split('T')[0]; // YYYY-MM-DD
}

// Function to record ONLY real traffic events (fallback)
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
                    
                    // 🔥 CRITICAL: Store visitor data in KV
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
                    
                    // 🔥 THIS LINE IS CRITICAL - Store in KV
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
        
        // Debug endpoint to check storage status
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


        // Enhanced visitor tracking endpoint
        if (req.url === '/api/v1/track-visitor' && req.method === 'POST') {
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
                        publisherId: auth.publisherId
                    };
                    
                    // Store in KV
                    await storage.storeVisitorSession(enhancedVisitorData);
                    
                    console.log(`👤 Visitor tracked and stored: ${realIP} from ${geolocation?.city}, ${geolocation?.country}`);
                    
                    res.status(200).json({
                        success: true,
                        message: 'Visitor tracked and stored successfully',
                        sessionId: enhancedVisitorData.sessionId,
                        geolocation: geolocation,
                        storage: 'kv'
                    });
                    
                } catch (error) {
                    console.error('Visitor tracking error:', error);
                    res.status(400).json({ error: 'Invalid visitor data' });
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
                // Get live visitors from KV
                const liveVisitors = await storage.getLiveVisitors();
                
                // Get daily stats from KV
                const dailyStats = await storage.getDailyStats();
                
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
                
                res.status(200).json({
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
                });
                
            } catch (error) {
                console.error('Real-time dashboard error:', error);
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
                    
                    // Generate API key based on plan
                    const plan = publisherInfo.plan || 'starter';
                    const apiKey = apiKeyManager.generateAPIKey(publisherId, plan);
                    
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
                    
                    // Fallback for existing hardcoded key
                    if (email === 'ashokvarma416@gmail.com' && 
                        apiKey === 'tc_live_1750227021440_5787761ba26d1f372a6ce3b5e62b69d2a8e0a58a814d2ff9_4d254583') {
                        
                        res.status(200).json({
                            success: true,
                            publisherName: 'Newsparrow',
                            plan: 'professional',
                            website: 'https://home.newsparrow.in'
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

        // Serve captcha challenge page
        if (req.method === 'GET') {
            const parsedUrl = url.parse(req.url, true);
            const pathname = parsedUrl.pathname;
            
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
            <strong>Instructions:</strong> Solve the math problem below to continue to the website
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
            Protected by Traffic Cop • AI-powered bot protection with KV storage
        </p>
    </div>

    <script>
        let mathAnswer = 0;
        let attempts = 0;
        let maxAttempts = 3;
        let sessionId = new URLSearchParams(window.location.search).get('session') || 'unknown';
        let website = new URLSearchParams(window.location.search).get('website') || 'newsparrow.in';
        
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
                        problem:
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

        // API key details endpoint
        if (req.url === '/api/v1/api-key/details' && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            try {
                const usage = await apiKeyManager.getAPIKeyUsage(auth.apiKey);
                
                res.status(200).json({
                    success: true,
                    apiKey: auth.apiKey.substring(0, 20) + '...',
                    publisherId: auth.publisherId,
                    plan: auth.plan,
                    website: auth.website,
                    usage: usage
                });
            } catch (error) {
                res.status(500).json({ error: 'Failed to get API key details' });
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

        // Debug endpoint to test KV storage directly
        if (req.url === '/api/v1/debug/test-kv' && req.method === 'POST') {
            try {
                await storage.ensureKVReady();
                
                // Test storing a simple value
                const testKey = 'tc_test_key';
                const testData = {
                    test: 'KV storage test',
                    timestamp: new Date().toISOString()
                };
                
                await kv.set(testKey, JSON.stringify(testData));
                
                // Try to retrieve it
                const retrieved = await kv.get(testKey);
                
                res.status(200).json({
                    success: true,
                    message: 'KV storage is working',
                    stored: testData,
                    retrieved: retrieved ? JSON.parse(retrieved) : null
                });
                
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: 'KV storage failed',
                    details: error.message
                });
            }
            return;
        }
        
        // Debug endpoint to check KV contents
        if (req.url === '/api/v1/debug/kv-contents' && req.method === 'GET') {
            try {
                await storage.ensureKVReady();
                
                // Check for session keys
                const sessionKeys = [];
                const dailyKeys = [];
                const activityKeys = [];
                
                // Scan for our keys (this might be limited in some KV implementations)
                try {
                    // Try to get specific keys we expect
                    const today = new Date().toISOString().split('T')[0];
                    const dailyStatsKey = `tc_daily:${today}`;
                    const dailyStats = await kv.get(dailyStatsKey);
                    
                    // Try to get activity log
                    const activityLog = await kv.lrange('tc_activity_log', 0, 10);
                    
                    res.status(200).json({
                        success: true,
                        today: today,
                        dailyStatsKey: dailyStatsKey,
                        dailyStatsExists: !!dailyStats,
                        dailyStatsContent: dailyStats,
                        activityLogLength: activityLog ? activityLog.length : 0,
                        activityLogSample: activityLog ? activityLog.slice(0, 2) : [],
                        kvPrefix: storage.kvPrefix
                    });
                    
                } catch (scanError) {
                    res.status(200).json({
                        success: false,
                        error: 'Could not scan KV',
                        details: scanError.message
                    });
                }
                
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: error.message
                });
            }
            return;
        }


        // Simplified KV test endpoint
        if (req.url === '/api/v1/test-kv-simple' && req.method === 'GET') {
            try {
                if (!kvReady) {
                    await initKV();
                }
                
                if (!kv) {
                    throw new Error('KV not initialized');
                }
                
                // Simple test
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
