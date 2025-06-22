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
    
    // Update daily stats (KV only) - FIXED JSON STORAGE
    async updateDailyStats(visitorData) {
        try {
            await this.ensureKVReady();
            
            const today = new Date().toISOString().split('T')[0];
            const statsKey = `${this.kvPrefix}daily:${today}`;
            
            console.log('🔄 Updating daily stats for key:', statsKey);
            
            let currentStats;
            try {
                const currentStatsStr = await kv.get(statsKey);
                
                // CRITICAL FIX: Handle both string and object responses
                if (currentStatsStr) {
                    if (typeof currentStatsStr === 'string') {
                        // It's already a JSON string, parse it
                        currentStats = JSON.parse(currentStatsStr);
                    } else if (typeof currentStatsStr === 'object') {
                        // It's already an object, use it directly
                        currentStats = currentStatsStr;
                    } else {
                        currentStats = null;
                    }
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
            
            // CRITICAL: Always store as JSON string
            const statsToStore = JSON.stringify(currentStats);
            await kv.setex(statsKey, 604800, statsToStore);
            console.log('✅ Daily stats stored as JSON string:', statsToStore);
            
        } catch (error) {
            console.error('❌ Daily stats error:', error);
            throw error;
        }
    }

    
    // Get daily statistics (KV only) - FIXED JSON PARSING
    async getDailyStats(date = null) {
        try {
            await this.ensureKVReady();
            
            const targetDate = date || new Date().toISOString().split('T')[0];
            const statsKey = `${this.kvPrefix}daily:${targetDate}`;
            
            console.log('📊 getDailyStats: Looking for key:', statsKey);
            
            const statsData = await kv.get(statsKey);
            console.log('📊 getDailyStats: Raw KV result type:', typeof statsData);
            console.log('📊 getDailyStats: Raw KV result:', statsData);
            
            if (statsData) {
                let stats;
                
                // CRITICAL FIX: Handle different data types
                if (typeof statsData === 'string') {
                    try {
                        stats = JSON.parse(statsData);
                        console.log('📊 Parsed JSON string successfully');
                    } catch (parseError) {
                        console.error('❌ Failed to parse JSON string:', parseError);
                        return this.getEmptyStats(targetDate);
                    }
                } else if (typeof statsData === 'object' && statsData !== null) {
                    // It's already an object, use it directly
                    stats = statsData;
                    console.log('📊 Using object data directly');
                } else {
                    console.log('📊 Invalid data type, returning empty stats');
                    return this.getEmptyStats(targetDate);
                }
                
                console.log('📊 Final stats:', stats);
                return stats;
            } else {
                console.log('📊 No data found, returning empty stats');
                return this.getEmptyStats(targetDate);
            }
            
        } catch (error) {
            console.error('❌ getDailyStats error:', error);
            return this.getEmptyStats(date);
        }
    }

    // Add this helper method
    getEmptyStats(date = null) {
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

    // Enhanced getLiveVisitors with unique IP counting
    async getLiveVisitors() {
        try {
            await this.ensureKVReady();
            
            console.log('👥 Getting live visitors from activity log...');
            
            const activityLog = await kv.lrange(`${this.kvPrefix}activity_log`, 0, -1);
            console.log('📋 Activity log entries found:', activityLog ? activityLog.length : 0);
            
            if (!activityLog || activityLog.length === 0) {
                console.log('📋 No activity log entries found');
                return [];
            }
            
            // Use 30-minute window for live visitors
            const thirtyMinutesAgo = Date.now() - (30 * 60 * 1000);
            const recentVisitors = [];
            const uniqueIPs = new Set(); // Track unique IPs
            
            for (let i = 0; i < activityLog.length; i++) {
                try {
                    const entry = activityLog[i];
                    let visitor;
                    
                    if (typeof entry === 'string') {
                        visitor = JSON.parse(entry);
                    } else {
                        visitor = entry;
                    }
                    
                    // Validate required fields
                    if (!visitor || !visitor.timestamp || !visitor.ipAddress) {
                        continue;
                    }
                    
                    const visitorTime = new Date(visitor.timestamp).getTime();
                    
                    if (visitorTime > thirtyMinutesAgo) {
                        // Only count unique IPs for live users
                        if (!uniqueIPs.has(visitor.ipAddress)) {
                            uniqueIPs.add(visitor.ipAddress);
                            recentVisitors.push(visitor);
                            console.log(`✅ Added unique IP visitor: ${visitor.ipAddress}`);
                        } else {
                            console.log(`⏭️ Skipped duplicate IP: ${visitor.ipAddress}`);
                        }
                    }
                } catch (parseError) {
                    console.warn('⚠️ Could not parse activity log entry:', parseError);
                }
            }
            
            console.log(`👥 Found ${recentVisitors.length} unique IP visitors from ${activityLog.length} total sessions`);
            return recentVisitors.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
        } catch (error) {
            console.error('❌ Get live visitors error:', error);
            return [];
        }
    }

    // Updated getActivityLogs to handle all entries
    async getActivityLogs(filter = 'today', page = 1, limit = 50) {
        try {
            await this.ensureKVReady();
            
            console.log('📋 Getting activity logs with filter:', filter);
            
            // Get all entries now that we know parsing works
            const activityLog = await kv.lrange(`${this.kvPrefix}activity_log`, 0, -1);
            console.log('📋 Raw entries found:', activityLog ? activityLog.length : 0);
            
            if (!activityLog || activityLog.length === 0) {
                return {
                    activities: [],
                    total: 0,
                    page: page,
                    limit: limit,
                    hasMore: false
                };
            }
            
            const activities = [];
            let successCount = 0;
            let errorCount = 0;
            
            for (let i = 0; i < activityLog.length; i++) {
                try {
                    const entry = activityLog[i];
                    let activity;
                    
                    if (typeof entry === 'string') {
                        activity = JSON.parse(entry);
                    } else {
                        activity = entry;
                    }
                    
                    // Validate required fields
                    if (activity && activity.timestamp && activity.sessionId) {
                        // Apply date filter
                        let includeActivity = true;
                        
                        if (filter === 'today') {
                            const activityDate = new Date(activity.timestamp);
                            const today = new Date().toISOString().split('T')[0];
                            const activityDay = activityDate.toISOString().split('T')[0];
                            includeActivity = activityDay === today;
                        }
                        
                        if (includeActivity) {
                            activities.push(activity);
                        }
                        successCount++;
                    } else {
                        errorCount++;
                    }
                    
                } catch (error) {
                    errorCount++;
                    console.log(`Parse error for entry ${i}:`, error.message);
                }
            }
            
            console.log(`📋 Parsing: ${successCount} success, ${errorCount} errors, ${activities.length} after filter`);
            
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
                hasMore: endIndex < activities.length,
                debug: {
                    rawCount: activityLog.length,
                    successCount: successCount,
                    errorCount: errorCount,
                    filteredCount: activities.length
                }
            };
            
        } catch (error) {
            console.error('❌ Activity logs error:', error);
            return {
                activities: [],
                total: 0,
                page: page,
                limit: limit,
                hasMore: false,
                error: error.message
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

// Enhanced DynamicBotDetector with proxycheck.io API Integration
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
        
        // UPDATED THRESHOLDS
        this.actionThresholds = global.trafficCopConfig?.thresholds || {
            challenge: 50, // Increased from 45
            block: 85      // Increased from 80
        };
        
        // proxycheck.io configuration with your API key
        this.proxycheckConfig = {
            apiKey: process.env.PROXYCHECK_API_KEY || '776969-1r4653-70557d-2317a9',
            baseUrl: 'https://proxycheck.io/v2/',
            timeout: 8000
        };
        
        console.log('🤖 Enhanced DynamicBotDetector with proxycheck.io API initialized');
    }
    
    // *** NEW: LEGITIMATE BOT CHECKER FUNCTION ***
    checkLegitimateBot(userAgent, ipAddress) {
        const legitimateBotsConfig = {
            google: {
                patterns: [/googlebot/i, /google-read-aloud/i],
                ipRanges: ['66.249.', '66.102.', '64.233.', '72.14.', '209.85.', '216.239.']
            },
            bing: {
                patterns: [/bingbot/i, /msnbot/i],
                ipRanges: ['40.77.', '157.55.', '207.46.', '65.52.']
            },
            facebook: {
                patterns: [/facebookexternalhit/i],
                ipRanges: ['69.171.', '66.220.', '173.252.', '31.13.']
            },
            twitter: {
                patterns: [/twitterbot/i],
                ipRanges: ['199.16.156.', '199.59.148.']
            }
        };
        
        for (const [botType, config] of Object.entries(legitimateBotsConfig)) {
            // Check user agent pattern
            const matchesPattern = config.patterns.some(pattern => pattern.test(userAgent));
            
            if (matchesPattern) {
                // Verify IP range
                const matchesIP = config.ipRanges.some(range => ipAddress.startsWith(range));
                
                if (matchesIP) {
                    return { isLegit: true, type: botType, verified: true };
                } else {
                    // User agent matches but IP doesn't - suspicious
                    return { isLegit: false, type: 'spoofed_bot', verified: false };
                }
            }
        }
        
        return { isLegit: false, type: null, verified: false };
    }
    
    // Enhanced VPN/Proxy Detection with proxycheck.io API
    async detectVPNProxy(ipAddress, userAgent, headers) {
        let vpnProxyScore = 0;
        const vpnProxySignals = [];
        
        try {
            // Method 1: Use proxycheck.io API (most accurate)
            const proxycheckResult = await this.checkProxyCheckIO(ipAddress);
            if (proxycheckResult.success) {
                vpnProxyScore += proxycheckResult.score;
                vpnProxySignals.push(...proxycheckResult.signals);
                console.log(`✅ proxycheck.io result: Score=${proxycheckResult.score}, Signals=[${proxycheckResult.signals.join(', ')}]`);
            }
            
            // Method 2: HTTP Headers Analysis (fallback/additional)
            const headerAnalysis = this.analyzeProxyHeaders(headers);
            vpnProxyScore += headerAnalysis.score;
            if (headerAnalysis.signals.length > 0) {
                vpnProxySignals.push(...headerAnalysis.signals);
            }
            
            // Method 3: Basic IP Analysis (additional verification)
            const ipAnalysis = await this.analyzeIPAddress(ipAddress);
            vpnProxyScore += ipAnalysis.score;
            if (ipAnalysis.signals.length > 0) {
                vpnProxySignals.push(...ipAnalysis.signals);
            }
            
        } catch (error) {
            console.warn('VPN/Proxy detection error:', error);
        }
        
        return {
            isVPNProxy: vpnProxyScore > 65, // Increased threshold for better accuracy
            confidence: Math.min(vpnProxyScore, 100),
            signals: vpnProxySignals,
            score: vpnProxyScore
        };
    }
    
    // NEW: proxycheck.io API integration
    async checkProxyCheckIO(ipAddress) {
        try {
            // Build comprehensive API URL with your key
            const apiUrl = `${this.proxycheckConfig.baseUrl}${ipAddress}?key=${this.proxycheckConfig.apiKey}&vpn=3&asn=1&risk=2&port=1&seen=1&days=7&tag=traffic-cop-newsparrow`;
            
            console.log(`🔍 Checking IP ${ipAddress} with proxycheck.io API...`);
            
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.proxycheckConfig.timeout);
            
            const response = await fetch(apiUrl, {
                method: 'GET',
                signal: controller.signal,
                headers: {
                    'User-Agent': 'Traffic-Cop-API/2.3'
                }
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`proxycheck.io API HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            console.log('📊 proxycheck.io API response:', data);
            
            if (data.status !== 'ok') {
                throw new Error(`proxycheck.io API status: ${data.status} - ${data.message || 'Unknown error'}`);
            }
            
            const ipData = data[ipAddress];
            if (!ipData) {
                throw new Error('No data returned for IP from proxycheck.io');
            }
            
            return this.parseProxyCheckResponse(ipData, ipAddress);
            
        } catch (error) {
            console.warn('⚠️ proxycheck.io API failed:', error.message);
            return { success: false, score: 0, signals: ['proxycheck_api_failed'] };
        }
    }
    
    // Parse proxycheck.io API response
    parseProxyCheckResponse(ipData, ipAddress) {
        let score = 0;
        const signals = [];

        console.log(`📊 Analyzing proxycheck.io data for ${ipAddress}:`, ipData);
        
        // Check proxy detection (primary indicator)
        if (ipData.proxy === 'yes') {
            score += 70; // High confidence for confirmed proxy
            signals.push('proxycheck_proxy_confirmed');
            
            // Add proxy type information
            if (ipData.type) {
                const typeStr = ipData.type.toLowerCase();
                signals.push(`proxy_type_${typeStr}`);
                
                // Different scores for different proxy types
                switch (typeStr) {
                    case 'vpn':
                        score += 25;
                        signals.push('proxycheck_vpn_confirmed');
                        break;
                    case 'socks':
                    case 'socks4':
                    case 'socks5':
                        score += 20;
                        signals.push('proxycheck_socks_proxy');
                        break;
                    case 'http':
                    case 'https':
                        score += 15;
                        signals.push('proxycheck_http_proxy');
                        break;
                    default:
                        score += 10;
                        signals.push('proxycheck_unknown_proxy_type');
                }
            }
            
            // Add port information if available
            if (ipData.port) {
                signals.push(`proxy_port_${ipData.port}`);
                
                // Common VPN/proxy ports get extra attention
                const suspiciousPorts = [1080, 1194, 3128, 8080, 8888, 9050];
                if (suspiciousPorts.includes(parseInt(ipData.port))) {
                    score += 10;
                    signals.push('suspicious_proxy_port');
                }
            }
            
            // Last seen information
            if (ipData.last_seen_human) {
                signals.push(`last_seen_${ipData.last_seen_human.replace(/\s+/g, '_')}`);
            }
        }
        
        // Check separate VPN detection
        if (ipData.vpn === 'yes') {
            score += 60;
            signals.push('proxycheck_vpn_detected');
        }
        
        // Use risk score from proxycheck.io (0-100 scale)
        if (ipData.risk !== undefined) {
            const riskScore = parseInt(ipData.risk);
            const riskContribution = Math.min(35, riskScore * 0.35); // Scale appropriately
            score += riskContribution;
            signals.push(`proxycheck_risk_${riskScore}`);
            
            console.log(`🎯 proxycheck.io risk score for ${ipAddress}: ${riskScore}% (contributing ${riskContribution} to total)`);
        }
        
        // Provider/ASN analysis
        if (ipData.provider) {
            const providerLower = ipData.provider.toLowerCase();
            
            // Check for suspicious keywords in provider name
            const suspiciousKeywords = ['vpn', 'proxy', 'hosting', 'datacenter', 'cloud', 'server', 'virtual'];
            suspiciousKeywords.forEach(keyword => {
                if (providerLower.includes(keyword)) {
                    score += 8;
                    signals.push(`suspicious_provider_${keyword}`);
                }
            });
            
            // Check for known VPN providers
            const knownVPNProviders = [
                'nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'purevpn',
                'protonvpn', 'mullvad', 'windscribe', 'tunnelbear', 'hotspot shield',
                'ipvanish', 'hidemyass', 'vyprvpn', 'torguard', 'perfectprivacy'
            ];
            
            knownVPNProviders.forEach(vpnProvider => {
                if (providerLower.includes(vpnProvider)) {
                    score += 50; // Very high score for known VPN providers
                    signals.push(`known_vpn_provider_${vpnProvider}`);
                }
            });
        }
        
        // Country-based adjustments
        if (ipData.country) {
            if (ipData.country === 'IN') {
                // Reduce score for Indian IPs to minimize false positives
                score = Math.max(0, score - 15);
                signals.push('indian_ip_adjustment');
                
                // Additional reduction for known Indian ISPs
                if (ipData.provider) {
                    const indianISPs = ['bharti', 'airtel', 'jio', 'bsnl', 'vodafone', 'idea'];
                    const providerLower = ipData.provider.toLowerCase();
                    
                    if (indianISPs.some(isp => providerLower.includes(isp))) {
                        score = Math.max(0, score - 10);
                        signals.push('indian_residential_isp');
                    }
                }
            } else {
                // Slight increase for foreign IPs
                score += 3;
                signals.push(`foreign_country_${ipData.country}`);
            }
        }
        
        // ASN analysis
        if (ipData.asn) {
            signals.push(`asn_${ipData.asn}`);
        }
        
        console.log(`✅ proxycheck.io analysis complete for ${ipAddress}: Score=${score}, Signals=[${signals.join(', ')}]`);
        
        return {
            success: true,
            score: score,
            signals: signals,
            rawData: ipData
        };
    }
    
    // Enhanced IP address analysis (fallback method)
    async analyzeIPAddress(ipAddress) {
        let score = 0;
        const signals = [];
        
        try {
            // Use ipapi.co as fallback for basic geolocation
            const response = await fetch(`https://ipapi.co/${ipAddress}/json/`);
            const data = await response.json();
            
            // Check for datacenter/hosting providers
            if (data.org) {
                const orgLower = data.org.toLowerCase();
                
                if (orgLower.includes('hosting')) {
                    score += 15; // Reduced since proxycheck.io is primary
                    signals.push('datacenter_hosting');
                }
                
                // Check for cloud providers
                const cloudProviders = ['amazon', 'google', 'microsoft', 'digitalocean', 'vultr', 'linode', 'ovh'];
                cloudProviders.forEach(provider => {
                    if (orgLower.includes(provider)) {
                        score += 12; // Reduced since proxycheck.io is primary
                        signals.push(`cloud_provider_${provider}`);
                    }
                });
                
                // Check for VPN keywords in ISP name
                const vpnKeywords = ['vpn', 'proxy', 'tunnel', 'private', 'secure', 'anonymous'];
                vpnKeywords.forEach(keyword => {
                    if (orgLower.includes(keyword)) {
                        score += 20; // Still significant as it's obvious
                        signals.push(`isp_vpn_keyword_${keyword}`);
                    }
                });
            }
            
        } catch (error) {
            console.warn('Fallback IP analysis failed:', error);
        }
        
        return { score, signals };
    }
    
    // Enhanced HTTP headers analysis
    analyzeProxyHeaders(headers) {
        let score = 0;
        const signals = [];
        
        // Check for proxy headers (reduced weight since proxycheck.io is primary)
        const proxyHeaders = [
            'x-forwarded-for',
            'x-real-ip',
            'via',
            'x-proxy-id',
            'x-forwarded-proto',
            'cf-connecting-ip',
            'x-cluster-client-ip'
        ];
        
        for (const header of proxyHeaders) {
            if (headers[header]) {
                score += 8; // Reduced from 15 since proxycheck.io is primary
                signals.push(`header_${header}`);
                
                // Multiple IPs in X-Forwarded-For indicates proxy chain
                if (header === 'x-forwarded-for' && headers[header].includes(',')) {
                    score += 12; // Reduced from 20
                    signals.push('proxy_chain_detected');
                }
            }
        }
        
        // Check for VPN-specific headers
        const vpnHeaders = ['x-vpn-client', 'x-tunnel-proto', 'x-anonymizer'];
        for (const header of vpnHeaders) {
            if (headers[header]) {
                score += 15;
                signals.push(`vpn_header_${header}`);
            }
        }
        
        return { score, signals };
    }
    
    // ISP analysis (simplified since proxycheck.io provides better data)
    async analyzeISP(ipAddress) {
        let score = 0;
        const signals = [];
        
        // This is now primarily handled by proxycheck.io
        // Keep minimal implementation for edge cases
        
        return { score, signals };
    }
    
    // *** UPDATED: Enhanced main detection with legitimate bot check FIRST ***
    async detectBot(requestData) {
        const sessionId = requestData.sessionId || 'unknown';
        const timestamp = Date.now();
        
        // *** CHECK LEGITIMATE BOTS FIRST ***
        const isLegitimateBot = this.checkLegitimateBot(
            requestData.userAgent, 
            requestData.ipAddress || requestData.realTimeData?.ipAddress
        );
        
        // If legitimate bot, give very low risk score
        if (isLegitimateBot.isLegit) {
            console.log(`✅ Legitimate ${isLegitimateBot.type} bot detected: ${requestData.ipAddress}`);
            return {
                riskScore: 5, // Very low risk for legitimate bots
                action: 'allow',
                confidence: 95,
                threats: [],
                blockAds: false,
                isBot: true,
                botType: isLegitimateBot.type,
                vpnProxy: { isVPN: false, confidence: 0 },
                analysis: {
                    legitimateBot: isLegitimateBot,
                    requestPattern: { frequency: 0, isRhythmic: false, totalRequests: 1 },
                    userAgentAnalysis: { score: 0.05, anomalies: [`Legitimate ${isLegitimateBot.type} bot`] },
                    behaviorAnalysis: { score: 1.0, signals: [] },
                    vpnProxyAnalysis: { isVPNProxy: false, confidence: 0, signals: [] }
                }
            };
        }
        
        // Continue with original bot detection for non-legitimate bots
        const requestAnalysis = this.analyzeRequestPatterns(sessionId, timestamp);
        const userAgentAnalysis = this.analyzeUserAgentAnomalies(requestData.userAgent);
        const behaviorAnalysis = this.analyzeBehaviorSignals(requestData.behaviorData || {});
        
        // Enhanced VPN/Proxy Detection with proxycheck.io
        const vpnProxyAnalysis = await this.detectVPNProxy(
            requestData.ipAddress || requestData.realTimeData?.ipAddress, 
            requestData.userAgent, 
            requestData.headers || {}
        );
        
        // Calculate composite risk score
        let riskScore = 0;
        const factors = [];
        
        // Original bot detection factors
        if (requestAnalysis.frequency > this.anomalyThresholds.requestFrequency.malicious) {
            riskScore += 40;
            factors.push(`High request frequency: ${requestAnalysis.frequency.toFixed(1)}/sec`);
        }
        
        if (requestAnalysis.isRhythmic && requestAnalysis.totalRequests > 5) {
            riskScore += 30;
            factors.push(`Mechanical request timing pattern`);
        }
        
        riskScore += userAgentAnalysis.score * 25; // REDUCED from 35
        if (userAgentAnalysis.anomalies.length > 0) {
            factors.push(`User agent anomalies: ${userAgentAnalysis.anomalies.join(', ')}`);
        }
        
        const behaviorRisk = (1 - behaviorAnalysis.score) * 30; // REDUCED from 40
        riskScore += behaviorRisk;
        if (behaviorAnalysis.signals.length > 0) {
            factors.push(`Behavioral signals: ${behaviorAnalysis.signals.join(', ')}`);
        }
        
        // Enhanced VPN/Proxy risk scoring
        riskScore += vpnProxyAnalysis.score;
        if (vpnProxyAnalysis.signals.length > 0) {
            factors.push(`VPN/Proxy signals: ${vpnProxyAnalysis.signals.join(', ')}`);
        }
        
        // Determine action with UPDATED THRESHOLDS
        let action = 'allow';
        let confidence = 0.6;
        let blockAds = false;
        
        const currentThresholds = global.trafficCopConfig?.thresholds || this.actionThresholds;
        
        if (riskScore >= currentThresholds.block) {
            action = 'block';
            confidence = 0.9;
            blockAds = true;
        } else if (riskScore >= currentThresholds.challenge) {
            action = 'challenge';
            confidence = 0.8;
        }
        
        // Enhanced ad blocking logic for VPN/Proxy users
        if (vpnProxyAnalysis.isVPNProxy) {
            blockAds = true;
            factors.push('Ad blocking enabled for VPN/Proxy user');
            
            // Log detailed VPN/Proxy information
            console.log(`🔍 VPN/Proxy user detected: IP=${requestData.ipAddress}, Confidence=${vpnProxyAnalysis.confidence}%, Signals=[${vpnProxyAnalysis.signals.join(', ')}]`);
        }
        
        console.log(`🎯 Enhanced Detection Complete: SessionId=${sessionId}, Risk=${Math.round(riskScore)}, VPN/Proxy=${vpnProxyAnalysis.isVPNProxy}, BlockAds=${blockAds}, Action=${action}`);
        
        return {
            riskScore: Math.round(riskScore),
            action: action,
            confidence: Math.round(confidence * 100),
            threats: factors,
            blockAds: blockAds,
            vpnProxy: vpnProxyAnalysis,
            analysis: {
                legitimateBot: isLegitimateBot,
                requestPattern: requestAnalysis,
                userAgentAnalysis: userAgentAnalysis,
                behaviorAnalysis: behaviorAnalysis,
                vpnProxyAnalysis: vpnProxyAnalysis
            }
        };
    }
    
    // Existing methods (keep unchanged)
    analyzeRequestPatterns(sessionId, timestamp) {
        if (!this.trafficPatterns.has(sessionId)) {
            this.trafficPatterns.set(sessionId, []);
        }
        
        const patterns = this.trafficPatterns.get(sessionId);
        patterns.push(timestamp);
        
        // Keep only last 10 requests
        if (patterns.length > 10) {
            patterns.shift();
        }
        
        // Calculate request frequency
        if (patterns.length < 2) {
            return { frequency: 0, isRhythmic: false, totalRequests: patterns.length };
        }
        
        const timeSpan = (patterns[patterns.length - 1] - patterns[0]) / 1000; // seconds
        const frequency = patterns.length / timeSpan;
        
        // Check for rhythmic patterns (bot-like)
        const intervals = [];
        for (let i = 1; i < patterns.length; i++) {
            intervals.push(patterns[i] - patterns[i - 1]);
        }
        
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((acc, interval) => acc + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
        const isRhythmic = variance < 1000; // Very consistent timing
        
        return {
            frequency: frequency,
            isRhythmic: isRhythmic,
            totalRequests: patterns.length,
            avgInterval: avgInterval,
            variance: variance
        };
    }
    
    // *** UPDATED: Enhanced user agent analysis with reduced bot penalties ***
    analyzeUserAgentAnomalies(userAgent) {
        const anomalies = [];
        let score = 0;
        
        if (!userAgent) {
            anomalies.push('Missing user agent');
            score = 1.0;
            return { score, anomalies };
        }
        
        const ua = userAgent.toLowerCase();
        
        // UPDATED: Legitimate bot indicators (very low penalty)
        const legitimateBotKeywords = [
            'googlebot', 'bingbot', 'facebookexternalhit', 'twitterbot',
            'linkedinbot', 'slackbot', 'whatsapp', 'telegrambot'
        ];
        
        let isLegitimateBot = false;
        for (const keyword of legitimateBotKeywords) {
            if (ua.includes(keyword)) {
                score += 0.05; // Very low penalty for legitimate bots
                isLegitimateBot = true;
                anomalies.push(`Legitimate bot: ${keyword}`);
                break;
            }
        }
        
        // If not a legitimate bot, check for other bot indicators
        if (!isLegitimateBot) {
            // Check for obvious bot keywords (high penalty)
            const obviousBots = [
                'python-requests', 'curl/', 'wget/', 'scrapy/', 'httpclient/',
                'java/', 'go-http-client', 'okhttp/', 'urllib', 'requests/'
            ];
            
            for (const bot of obviousBots) {
                if (ua.includes(bot)) {
                    score += 0.8; // High penalty for obvious bots
                    anomalies.push(`Obvious bot: ${bot}`);
                    break;
                }
            }
            
            // Check for headless browser indicators (moderate penalty)
            const headlessIndicators = [
                'headless', 'phantomjs', 'selenium', 'webdriver', 'puppeteer'
            ];
            
            for (const indicator of headlessIndicators) {
                if (ua.includes(indicator)) {
                    score += 0.5; // Moderate penalty
                    anomalies.push(`Headless browser: ${indicator}`);
                    break;
                }
            }
            
            // Generic "bot" keyword (REDUCED penalty)
            if (ua.includes('bot')) {
                score += 0.15; // REDUCED from 0.3
                anomalies.push('Generic bot keyword');
            }
        }
        
        // Check for unusual patterns
        if (ua.length < 20) {
            anomalies.push('Unusually short user agent');
            score += 0.2;
        }
        
        if (ua.length > 500) {
            anomalies.push('Unusually long user agent');
            score += 0.2;
        }
        
        // Check for missing common browser indicators
        const browserIndicators = ['mozilla', 'webkit', 'chrome', 'safari', 'firefox', 'edge'];
        const hasIndicators = browserIndicators.some(indicator => ua.includes(indicator));
        
        if (!hasIndicators && !isLegitimateBot) {
            anomalies.push('Missing browser indicators');
            score += 0.4;
        }
        
        return {
            score: Math.min(1.0, score),
            anomalies: anomalies
        };
    }
    
    analyzeBehaviorSignals(behaviorData) {
        const signals = [];
        let score = 0.8; // Start with high human score
        
        // Check mouse movements
        if (!behaviorData.mouseMovements || behaviorData.mouseMovements === 0) {
            signals.push('no_mouse_movement');
            score -= 0.3;
        }
        
        // Check clicks
        if (!behaviorData.clicks || behaviorData.clicks === 0) {
            signals.push('no_clicks');
            score -= 0.2;
        }
        
        // Check keyboard events
        if (!behaviorData.keystrokes || behaviorData.keystrokes === 0) {
            signals.push('no_keyboard_interaction');
            score -= 0.2;
        }
        
        // Check scroll events
        if (!behaviorData.scrollEvents || behaviorData.scrollEvents === 0) {
            signals.push('no_scroll_activity');
            score -= 0.1;
        }
        
        // Check for unnatural timing
        if (behaviorData.avgClickSpeed && behaviorData.avgClickSpeed < 100) {
            signals.push('unnatural_click_timing');
            score -= 0.3;
        }
        
        // Check mouse movement variation
        if (behaviorData.mouseVariation && behaviorData.mouseVariation < 10) {
            signals.push('unnatural_mouse_timing');
            score -= 0.2;
        }
        
        return {
            score: Math.max(0, Math.min(1, score)),
            signals: signals
        };
    }
}

// Global function to create and use the detector
async function analyzeTrafficDynamic(userAgent, website, requestData) {
    const detector = new DynamicBotDetector();
    return await detector.detectBot(requestData);
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DynamicBotDetector, analyzeTrafficDynamic };
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
                version: '5.1.0',
                features: ['Dynamic Bot Detection', 'KV Persistent Storage', 'Dynamic API Keys', 'Real-Time Analytics', 'Global Timezone Support', 'Geolocation Tracking', 'Legitimate Bot Detection']
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
                        challenge: detector.actionThresholds?.challenge || 50,
                        block: detector.actionThresholds?.block || 85
                    },
                    anomalyThresholds: detector.anomalyThresholds,
                    version: '5.1.0',
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
                            challenge: newConfig.thresholds.challenge || 50,
                            block: newConfig.thresholds.block || 85
                        };
                        
                        console.log('🔧 Configuration updated:', global.trafficCopConfig.thresholds);
                    }
                    
                    res.status(200).json({
                        success: true,
                        message: 'Configuration updated successfully',
                        updatedConfig: {
                            thresholds: global.trafficCopConfig?.thresholds || { challenge: 50, block: 85 },
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

        // Enhanced analyze endpoint with VPN/Proxy detection
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
                    
                    // Get all headers for VPN/proxy analysis
                    const allHeaders = req.headers;
                    
                    // Enhanced request data with headers and IP
                    const enhancedRequestData = {
                        ...requestData,
                        ipAddress: realIP,
                        headers: allHeaders
                    };
                    
                    // Use enhanced bot detection
                    const detector = new DynamicBotDetector();
                    const analysis = await detector.detectBot(enhancedRequestData);
                    
                    // Store visitor data in KV
                    const visitorData = {
                        sessionId: requestData.sessionId || `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                        userAgent: userAgent,
                        website: website,
                        ipAddress: realIP,
                        riskScore: analysis.riskScore,
                        action: analysis.action,
                        threats: analysis.threats,
                        blockAds: analysis.blockAds,
                        vpnProxy: analysis.vpnProxy,
                        publisherId: auth.publisherId,
                        timestamp: new Date().toISOString()
                    };
                    
                    await storage.storeVisitorSession(visitorData);
                    
                    // Get geolocation data
                    const geolocation = await getGeolocationFromIP(realIP);
                    if (geolocation) {
                        visitorData.geolocation = geolocation;
                    }
                    
                    // Calculate severity
                    const severity = calculateSeverity(analysis.riskScore);
                    
                    // Enhanced response with all analysis data
                    res.status(200).json({
                        riskScore: analysis.riskScore,
                        action: analysis.action,
                        confidence: analysis.confidence,
                        threats: analysis.threats,
                        blockAds: analysis.blockAds,
                        vpnProxy: analysis.vpnProxy,
                        severity: severity,
                        sessionId: visitorData.sessionId,
                        ipAddress: realIP,
                        geolocation: geolocation,
                        timestamp: new Date().toISOString(),
                        analysis: analysis.analysis,
                        isBot: analysis.isBot || false,
                        botType: analysis.botType || null
                    });
                    
                } catch (error) {
                    console.error('❌ Analysis endpoint error:', error);
                    res.status(500).json({
                        error: 'Analysis failed',
                        details: error.message,
                        timestamp: new Date().toISOString()
                    });
                }
            });
            return;
        }

        // Real-time dashboard endpoint
        if (req.url === '/api/v1/real-time-dashboard' && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            try {
                // Get daily stats
                const dailyStats = await storage.getDailyStats();
                
                // Get live visitors (last 30 minutes)
                const liveVisitors = await storage.getLiveVisitors();
                
                // Calculate live stats
                const liveStats = {
                    onlineUsers: liveVisitors.length,
                    botsDetected: liveVisitors.filter(v => v.action === 'block').length,
                    botSeverity: {
                        critical: liveVisitors.filter(v => v.riskScore >= 80).length,
                        high: liveVisitors.filter(v => v.riskScore >= 60 && v.riskScore < 80).length,
                        medium: liveVisitors.filter(v => v.riskScore >= 40 && v.riskScore < 60).length,
                        low: liveVisitors.filter(v => v.riskScore >= 20 && v.riskScore < 40).length,
                        minimal: liveVisitors.filter(v => v.riskScore < 20).length
                    }
                };
                
                // Format live visitors for dashboard
                const formattedVisitors = liveVisitors.map(visitor => ({
                    ...visitor,
                    lastSeenFormatted: formatTimeAgo(visitor.timestamp),
                    severity: calculateSeverity(visitor.riskScore)
                }));
                
                // Geographic stats
                const geographicStats = {
                    countries: Object.entries(dailyStats.countries || {})
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 10)
                        .map(([country, count]) => ({ country, count })),
                    cities: Object.entries(dailyStats.cities || {})
                        .sort(([,a], [,b]) => b - a)
                        .slice(0, 10)
                        .map(([city, count]) => ({ city, count }))
                };
                
                res.status(200).json({
                    success: true,
                    timestamp: new Date().toISOString(),
                    dailyStats: dailyStats,
                    liveStats: liveStats,
                    onlineVisitors: formattedVisitors,
                    geographicStats: geographicStats,
                    publisherId: auth.publisherId,
                    website: auth.website
                });
                
            } catch (error) {
                console.error('❌ Dashboard endpoint error:', error);
                res.status(500).json({
                    error: 'Dashboard data fetch failed',
                    details: error.message
                });
            }
            return;
        }

        // Activity logs endpoint
        if (req.url.startsWith('/api/v1/activity-logs') && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            try {
                const urlParts = url.parse(req.url, true);
                const filter = urlParts.query.filter || 'today';
                const page = parseInt(urlParts.query.page) || 1;
                const limit = parseInt(urlParts.query.limit) || 50;
                
                const activityData = await storage.getActivityLogs(filter, page, limit);
                
                // Format activity logs
                const formattedActivities = activityData.activities.map(activity => ({
                    ...activity,
                    timestampFormatted: formatTimeAgo(activity.timestamp),
                    severity: calculateSeverity(activity.riskScore)
                }));
                
                res.status(200).json({
                    success: true,
                    activities: formattedActivities,
                    pagination: {
                        total: activityData.total,
                        page: activityData.page,
                        limit: activityData.limit,
                        hasMore: activityData.hasMore
                    },
                    filter: filter,
                    debug: activityData.debug
                });
                
            } catch (error) {
                console.error('❌ Activity logs endpoint error:', error);
                res.status(500).json({
                    error: 'Activity logs fetch failed',
                    details: error.message
                });
            }
            return;
        }

        // Analytics endpoint
        if (req.url === '/api/v1/analytics' && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            try {
                const dailyStats = await storage.getDailyStats();
                const liveVisitors = await storage.getLiveVisitors();
                
                // Calculate analytics
                const analytics = {
                    totalRequests: dailyStats.totalRequests,
                    blockedBots: dailyStats.blockedBots,
                    allowedUsers: dailyStats.allowedUsers,
                    challengedUsers: dailyStats.challengedUsers,
                    blockRate: dailyStats.totalRequests > 0 ? 
                        Math.round((dailyStats.blockedBots / dailyStats.totalRequests) * 100) : 0,
                    liveUsers: liveVisitors.length,
                    topThreats: dailyStats.threats || [],
                    geographic: {
                        countries: dailyStats.countries || {},
                        cities: dailyStats.cities || {}
                    }
                };
                
                res.status(200).json({
                    success: true,
                    analytics: analytics,
                    timestamp: new Date().toISOString()
                });
                
            } catch (error) {
                console.error('❌ Analytics endpoint error:', error);
                res.status(500).json({
                    error: 'Analytics fetch failed',
                    details: error.message
                });
            }
            return;
        }

        // Publisher signup endpoint
        if (req.url === '/api/v1/publisher/signup' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const signupData = JSON.parse(body);
                    const { email, publisherName, website, plan = 'starter' } = signupData;
                    
                    // Validate required fields
                    if (!email || !publisherName || !website) {
                        res.status(400).json({
                            error: 'Missing required fields',
                            required: ['email', 'publisherName', 'website']
                        });
                        return;
                    }
                    
                    // Check if publisher already exists
                    const existingPublisher = await apiKeyManager.getPublisherByEmail(email);
                    if (existingPublisher) {
                        res.status(409).json({
                            error: 'Publisher already exists',
                            message: 'A publisher with this email already exists'
                        });
                        return;
                    }
                    
                    // Generate new API key
                    const publisherId = `pub_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
                    const apiKey = apiKeyManager.generateAPIKey({ email, publisherId });
                    
                    // Store publisher data
                    const publisherData = {
                        publisherId: publisherId,
                        apiKey: apiKey,
                        email: email,
                        publisherName: publisherName,
                        website: website,
                        plan: plan
                    };
                    
                    await apiKeyManager.storeAPIKey(publisherData);
                    
                    res.status(201).json({
                        success: true,
                        message: 'Publisher account created successfully',
                        publisherId: publisherId,
                        apiKey: apiKey,
                        plan: plan,
                        website: website
                    });
                    
                } catch (error) {
                    console.error('❌ Publisher signup error:', error);
                    res.status(500).json({
                        error: 'Signup failed',
                        details: error.message
                    });
                }
            });
            return;
        }

        // Publisher login endpoint
        if (req.url === '/api/v1/publisher/login' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const loginData = JSON.parse(body);
                    const { email } = loginData;
                    
                    if (!email) {
                        res.status(400).json({
                            error: 'Email is required'
                        });
                        return;
                    }
                    
                    // Get publisher by email
                    const publisher = await apiKeyManager.getPublisherByEmail(email);
                    
                    if (!publisher) {
                        res.status(404).json({
                            error: 'Publisher not found',
                            message: 'No publisher found with this email'
                        });
                        return;
                    }
                    
                    // Create session token
                    const sessionToken = Buffer.from(publisher.apiKey).toString('base64');
                    
                    res.status(200).json({
                        success: true,
                        message: 'Login successful',
                        sessionToken: sessionToken,
                        publisherId: publisher.publisherId,
                        publisherName: publisher.publisherName,
                        website: publisher.website,
                        plan: publisher.plan
                    });
                    
                } catch (error) {
                    console.error('❌ Publisher login error:', error);
                    res.status(500).json({
                        error: 'Login failed',
                        details: error.message
                    });
                }
            });
            return;
        }

        // Challenge verification endpoint
        if (req.url === '/api/v1/verify-challenge' && req.method === 'POST') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const challengeData = JSON.parse(body);
                    const { sessionId, challengeResponse } = challengeData;
                    
                    // Simple challenge verification (can be enhanced)
                    const isValid = challengeResponse && challengeResponse.length > 0;
                    
                    if (isValid) {
                        // Update session to allow access
                        const updatedData = {
                            sessionId: sessionId,
                            challengePassed: true,
                            action: 'allow',
                            timestamp: new Date().toISOString()
                        };
                        
                        await storage.storeVisitorSession(updatedData);
                        
                        res.status(200).json({
                            success: true,
                            action: 'allow',
                            message: 'Challenge passed successfully'
                        });
                    } else {
                        res.status(400).json({
                            success: false,
                            action: 'block',
                            message: 'Challenge failed'
                        });
                    }
                    
                } catch (error) {
                    console.error('❌ Challenge verification error:', error);
                    res.status(500).json({
                        error: 'Challenge verification failed',
                        details: error.message
                    });
                }
            });
            return;
        }

        // 404 for unknown endpoints
        res.status(404).json({
            error: 'Endpoint not found',
            availableEndpoints: [
                'GET /health',
                'GET /api/v1/config',
                'POST /api/v1/config',
                'POST /api/v1/analyze',
                'GET /api/v1/real-time-dashboard',
                'GET /api/v1/activity-logs',
                'GET /api/v1/analytics',
                'POST /api/v1/publisher/signup',
                'POST /api/v1/publisher/login',
                'POST /api/v1/verify-challenge'
            ]
        });

    } catch (error) {
        console.error('❌ Server error:', error);
        res.status(500).json({
            error: 'Internal server error',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
};

// Helper function to format time ago
function formatTimeAgo(timestamp) {
    const now = new Date();
    const time = new Date(timestamp);
    const diffInSeconds = Math.floor((now - time) / 1000);
    
    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    return `${Math.floor(diffInSeconds / 86400)}d ago`;
}

