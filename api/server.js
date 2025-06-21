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


    
    // Fixed getLiveVisitors method
    async getLiveVisitors() {
        try {
            await this.ensureKVReady();
            
            console.log('👥 Getting live visitors from activity log...');
            
            // Use the same logic as the working getActivityLogs
            const activityLog = await kv.lrange(`${this.kvPrefix}activity_log`, 0, -1);
            console.log('📋 Activity log entries found:', activityLog ? activityLog.length : 0);
            
            if (!activityLog || activityLog.length === 0) {
                console.log('📋 No activity log entries found');
                return [];
            }
            
            // Use 30-minute window for live visitors (more realistic)
            const thirtyMinutesAgo = Date.now() - (30 * 60 * 1000);
            const recentVisitors = [];
            const uniqueSessions = new Set();
            
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
                    if (!visitor || !visitor.timestamp || !visitor.sessionId) {
                        continue;
                    }
                    
                    const visitorTime = new Date(visitor.timestamp).getTime();
                    
                    console.log(`🕒 Checking visitor: ${visitor.sessionId}, Time: ${new Date(visitorTime).toISOString()}, Cutoff: ${new Date(thirtyMinutesAgo).toISOString()}`);
                    
                    if (visitorTime > thirtyMinutesAgo) {
                        // Only count unique sessions as "live users"
                        if (!uniqueSessions.has(visitor.sessionId)) {
                            uniqueSessions.add(visitor.sessionId);
                            recentVisitors.push(visitor);
                            console.log(`✅ Added recent visitor: ${visitor.sessionId}`);
                        }
                    }
                } catch (parseError) {
                    console.warn('⚠️ Could not parse activity log entry:', parseError);
                }
            }
            
            console.log('👥 Found recent unique visitors:', recentVisitors.length);
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
        
        this.actionThresholds = global.trafficCopConfig?.thresholds || {
            challenge: 40,
            block: 75
        };
        
        // proxycheck.io configuration with your API key
        this.proxycheckConfig = {
            apiKey: process.env.PROXYCHECK_API_KEY || '776969-1r4653-70557d-2317a9',
            baseUrl: 'https://proxycheck.io/v2/',
            timeout: 8000
        };
        
        console.log('🤖 Enhanced DynamicBotDetector with proxycheck.io API initialized');
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
    
    // Enhanced main detection with improved VPN/Proxy integration
    async detectBot(requestData) {
        const sessionId = requestData.sessionId || 'unknown';
        const timestamp = Date.now();
        
        // Original bot detection methods
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
        
        riskScore += userAgentAnalysis.score * 35;
        if (userAgentAnalysis.anomalies.length > 0) {
            factors.push(`User agent anomalies: ${userAgentAnalysis.anomalies.join(', ')}`);
        }
        
        const behaviorRisk = (1 - behaviorAnalysis.score) * 40;
        riskScore += behaviorRisk;
        if (behaviorAnalysis.signals.length > 0) {
            factors.push(`Behavioral signals: ${behaviorAnalysis.signals.join(', ')}`);
        }
        
        // Enhanced VPN/Proxy risk scoring
        riskScore += vpnProxyAnalysis.score;
        if (vpnProxyAnalysis.signals.length > 0) {
            factors.push(`VPN/Proxy signals: ${vpnProxyAnalysis.signals.join(', ')}`);
        }
        
        // Determine action with enhanced logic
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
    
    analyzeUserAgentAnomalies(userAgent) {
        const anomalies = [];
        let score = 0;
        
        if (!userAgent) {
            anomalies.push('Missing user agent');
            score = 1.0;
            return { score, anomalies };
        }
        
        const ua = userAgent.toLowerCase();
        
        // Check for bot keywords
        const botKeywords = ['bot', 'crawler', 'spider', 'scraper', 'headless', 'phantom', 'selenium', 'python', 'curl', 'wget'];
        botKeywords.forEach(keyword => {
            if (ua.includes(keyword)) {
                anomalies.push(`Bot keyword: ${keyword}`);
                score += 0.3;
            }
        });
        
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
        
        if (!hasIndicators) {
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
                    
                    const response = {
                        sessionId: visitorData.sessionId,
                        publisherId: auth.publisherId,
                        website,
                        riskScore: analysis.riskScore,
                        action: analysis.action,
                        confidence: analysis.confidence,
                        threats: analysis.threats,
                        blockAds: analysis.blockAds,
                        vpnProxy: analysis.vpnProxy,
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

        // Enhanced real-time dashboard with better live user calculation
        if (req.url === '/api/v1/real-time-dashboard' && req.method === 'GET') {
            const auth = await authenticateAPIKey(req);
            
            if (!auth.authenticated) {
                res.status(401).json({ error: auth.error });
                return;
            }
            
            const userTimezone = req.headers['x-user-timezone'] || 'UTC';
            
            try {
                console.log('🔍 Dashboard: Getting live visitors...');
                const liveVisitors = await storage.getLiveVisitors();
                console.log('👥 Dashboard: Live visitors count:', liveVisitors.length);
                
                console.log('📊 Dashboard: Getting daily stats...');
                const dailyStats = await storage.getDailyStats();
                console.log('📊 Dashboard: Daily stats:', dailyStats);
                
                // ENHANCED: Better live user calculation
                const currentTime = Date.now();
                const fiveMinutesAgo = currentTime - (5 * 60 * 1000);
                const tenMinutesAgo = currentTime - (10 * 60 * 1000);
                
                // Count users active in last 5 minutes as "live"
                const veryRecentVisitors = liveVisitors.filter(visitor => {
                    const visitorTime = new Date(visitor.timestamp).getTime();
                    return visitorTime > fiveMinutesAgo && visitor.action !== 'block';
                });
                
                // Count users active in last 10 minutes for total visitors
                const recentVisitors = liveVisitors.filter(visitor => {
                    const visitorTime = new Date(visitor.timestamp).getTime();
                    return visitorTime > tenMinutesAgo;
                });
                
                // Calculate bot statistics
                const botStats = {
                    total: liveVisitors.filter(v => v.action === 'block').length,
                    critical: liveVisitors.filter(v => (v.riskScore || 0) >= 80).length,
                    high: liveVisitors.filter(v => (v.riskScore || 0) >= 60 && (v.riskScore || 0) < 80).length,
                    medium: liveVisitors.filter(v => (v.riskScore || 0) >= 40 && (v.riskScore || 0) < 60).length,
                    low: liveVisitors.filter(v => (v.riskScore || 0) >= 20 && (v.riskScore || 0) < 40).length,
                    minimal: liveVisitors.filter(v => (v.riskScore || 0) < 20).length
                };
                
                // ENHANCED: Calculate fields with better logic
                const totalBotsDetected = (dailyStats.blockedBots || 0) + (dailyStats.challengedUsers || 0);
                const onlineUsers = veryRecentVisitors.length; // Users active in last 5 minutes
                
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
                        onlineUsers: onlineUsers, // ENHANCED: Better calculation
                        totalVisitors: recentVisitors.length, // 10-minute window
                        botsDetected: totalBotsDetected,
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
                    storage: 'kv',
                    debug: {
                        liveVisitorsTotal: liveVisitors.length,
                        veryRecentCount: veryRecentVisitors.length,
                        recentCount: recentVisitors.length,
                        timeWindows: {
                            fiveMinutesAgo: new Date(fiveMinutesAgo).toISOString(),
                            tenMinutesAgo: new Date(tenMinutesAgo).toISOString()
                        }
                    }
                };
                
                console.log('📤 Enhanced dashboard response:', {
                    onlineUsers: response.liveStats.onlineUsers,
                    totalVisitors: response.liveStats.totalVisitors,
                    botsDetected: response.liveStats.botsDetected,
                    debug: response.debug
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

        // Fixed KV contents debug endpoint
        if (req.url === '/api/v1/debug/kv-contents' && req.method === 'GET') {
            try {
                await storage.ensureKVReady();
                
                const today = new Date().toISOString().split('T')[0];
                const dailyStatsKey = `tc_daily:${today}`;
                
                const dailyStatsRaw = await kv.get(dailyStatsKey);
                const activityLogRaw = await kv.lrange('tc_activity_log', 0, 10); // Get first 10 entries
                
                console.log('🔍 KV Contents - Activity log raw:', activityLogRaw);
                
                let dailyStatsContent = null;
                if (dailyStatsRaw) {
                    try {
                        dailyStatsContent = typeof dailyStatsRaw === 'string' ? JSON.parse(dailyStatsRaw) : dailyStatsRaw;
                    } catch (error) {
                        dailyStatsContent = { error: 'Parse failed', raw: dailyStatsRaw };
                    }
                }
                
                // FIXED: Parse activity log sample
                let activityLogSample = [];
                if (activityLogRaw && activityLogRaw.length > 0) {
                    for (const entry of activityLogRaw.slice(0, 3)) {
                        try {
                            activityLogSample.push(JSON.parse(entry));
                        } catch (error) {
                            activityLogSample.push({ error: 'Parse failed', raw: entry });
                        }
                    }
                }
                
                res.status(200).json({
                    success: true,
                    today: today,
                    dailyStatsKey: dailyStatsKey,
                    dailyStatsExists: !!dailyStatsRaw,
                    dailyStatsContent: dailyStatsContent,
                    activityLogLength: activityLogRaw ? activityLogRaw.length : 0,
                    activityLogSample: activityLogSample, // FIXED: Parsed sample
                    kvPrefix: storage.kvPrefix
                });
                
            } catch (error) {
                console.error('❌ KV contents debug error:', error);
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
