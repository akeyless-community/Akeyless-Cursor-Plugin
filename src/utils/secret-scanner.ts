import * as vscode from 'vscode';
import { logger } from './logger';

export interface HardcodedSecret {
    fileName: string;
    lineNumber: number;
    column: number;
    value: string;
    type: string;
    context: string;
}

export class SecretScanner {
    private static readonly SECRET_PATTERNS = [
        // Cloud Provider Keys
        {
            name: 'Google API Key',
            pattern: /AIza[0-9A-Za-z\-_]{35}/g,
            suggestion: 'Google API Key',
            confidence: 'high'
        },
        {
            name: 'AWS Access Key',
            pattern: /AKIA[0-9A-Z]{16}/g,
            suggestion: 'AWS Access Key',
            confidence: 'high'
        },
        {
            name: 'AWS Secret Key',
            pattern: /(?:aws[_-]?secret[_-]?key|aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*["']?([0-9a-zA-Z/+]{40})["']?/gi,
            suggestion: 'AWS Secret Key',
            confidence: 'high'
        },
        {
            name: 'AWS Session Token',
            pattern: /(?:aws[_-]?session[_-]?token|session_token)\s*[:=]\s*["']?([A-Za-z0-9+/]{300,})["']?/gi,
            suggestion: 'AWS Session Token',
            confidence: 'high'
        },
        {
            name: 'Azure Storage Account Key',
            pattern: /(?:azure[_-]?storage[_-]?account[_-]?key|storage[_-]?account[_-]?key|accountkey)\s*[:=]\s*["']?([a-zA-Z0-9/+]{88})["']?/gi,
            suggestion: 'Azure Storage Account Key',
            confidence: 'high'
        },
        {
            name: 'GCP Service Account Key',
            pattern: /"type":\s*"service_account".*"private_key":\s*"-----BEGIN\s+PRIVATE\s+KEY-----/gs,
            suggestion: 'GCP Service Account Key',
            confidence: 'high'
        },
        
        // API Keys & Tokens
        {
            name: 'GitHub Token',
            pattern: /gh[po][_][0-9a-zA-Z]{36}/g,
            suggestion: 'GitHub Token',
            confidence: 'high'
        },
        {
            name: 'GitHub App Token',
            pattern: /ghs_[a-zA-Z0-9]{36}/g,
            suggestion: 'GitHub App Token',
            confidence: 'high'
        },
        {
            name: 'Slack Token',
            pattern: /xox[p|b|o|a]-[A-Za-z0-9-]+/g,
            suggestion: 'Slack Token',
            confidence: 'high'
        },
        {
            name: 'Stripe Key',
            pattern: /sk_live_[0-9a-zA-Z]{24}/g,
            suggestion: 'Stripe Key',
            confidence: 'high'
        },
        {
            name: 'Stripe Publishable Key',
            pattern: /pk_live_[0-9a-zA-Z]{24}/g,
            suggestion: 'Stripe Publishable Key',
            confidence: 'high'
        },
        {
            name: 'Stripe Test Key',
            pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
            suggestion: 'Stripe Test Key',
            confidence: 'high'
        },
        {
            name: 'Stripe Restricted Key',
            pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
            suggestion: 'Stripe Restricted Key',
            confidence: 'high'
        },
        {
            name: 'Firebase Key',
            pattern: /AIza[0-9A-Za-z\-_]{35}/g,
            suggestion: 'Firebase Key',
            confidence: 'high'
        },
        {
            name: 'Discord Bot Token',
            pattern: /[MN][a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}/g,
            suggestion: 'Discord Bot Token',
            confidence: 'high'
        },
        {
            name: 'Telegram Bot Token',
            pattern: /[0-9]{8,10}:[a-zA-Z0-9_-]{35}/g,
            suggestion: 'Telegram Bot Token',
            confidence: 'high'
        },
        
        // Cryptographic Keys
        {
            name: 'Private Key',
            pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\\s\\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
            suggestion: 'Private Key',
            confidence: 'high'
        },
        {
            name: 'SSH Private Key',
            pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\\s\\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
            suggestion: 'SSH Private Key',
            confidence: 'high'
        },
        {
            name: 'PGP Private Key',
            pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
            suggestion: 'PGP Private Key',
            confidence: 'high'
        },
        
        // Tokens & Authentication
        {
            name: 'JWT Token',
            pattern: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*/g,
            suggestion: 'JWT Token',
            confidence: 'high'
        },
        {
            name: 'OAuth Token',
            pattern: /(?:oauth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-._~+/]{20,})["']?/gi,
            suggestion: 'OAuth Token',
            confidence: 'medium'
        },
        
        // Database Credentials
        {
            name: 'MongoDB Connection String',
            pattern: /mongodb(\+srv)?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
            suggestion: 'MongoDB Connection String',
            confidence: 'high'
        },
        {
            name: 'PostgreSQL Connection String',
            pattern: /postgresql:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
            suggestion: 'PostgreSQL Connection String',
            confidence: 'high'
        },
        {
            name: 'MySQL Connection String',
            pattern: /mysql:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
            suggestion: 'MySQL Connection String',
            confidence: 'high'
        },
        
        // MEDIUM CONFIDENCE PATTERNS (Context-based detection)
        {
            name: 'Gemini API Key',
            pattern: /(?:gemini[_-]?api[_-]?key|gemini_api_key|GeminiAPIKey)\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
            suggestion: 'Gemini API Key',
            confidence: 'medium'
        },
        {
            name: 'OpenAI API Key',
            pattern: /(?:openai[_-]?api[_-]?key|openai_api_key)\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
            suggestion: 'OpenAI API Key',
            confidence: 'medium'
        },
        {
            name: 'OpenAI API Key (sk- prefix)',
            pattern: /sk-[A-Za-z0-9]{32,}/g,
            suggestion: 'OpenAI API Key',
            confidence: 'high'
        },
        {
            name: 'Anthropic API Key',
            pattern: /sk-ant-[A-Za-z0-9\-_]{95,}/g,
            suggestion: 'Anthropic API Key',
            confidence: 'high'
        },
        {
            name: 'Twilio API Key',
            pattern: /SK[0-9a-fA-F]{32}/g,
            suggestion: 'Twilio API Key',
            confidence: 'high'
        },
        {
            name: 'Twilio Auth Token',
            pattern: /(?:twilio[_-]?auth[_-]?token|twilio[_-]?token)\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?/gi,
            suggestion: 'Twilio Auth Token',
            confidence: 'high'
        },
        {
            name: 'SendGrid API Key',
            pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
            suggestion: 'SendGrid API Key',
            confidence: 'high'
        },
        {
            name: 'Mailgun API Key',
            pattern: /(?:mailgun[_-]?api[_-]?key|mailgun[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
            suggestion: 'Mailgun API Key',
            confidence: 'high'
        },
        {
            name: 'Heroku API Key',
            pattern: /(?:heroku[_-]?api[_-]?key|heroku[_-]?key)\s*[:=]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
            suggestion: 'Heroku API Key',
            confidence: 'high'
        },
        {
            name: 'Square Access Token',
            pattern: /EAAA[a-zA-Z0-9]{60,}/g,
            suggestion: 'Square Access Token',
            confidence: 'high'
        },
        {
            name: 'Shopify Shared Secret',
            pattern: /shpss_[a-f0-9]{32,}/g,
            suggestion: 'Shopify Shared Secret',
            confidence: 'high'
        },
        {
            name: 'Shopify Access Token',
            pattern: /shpat_[a-f0-9]{32,}/g,
            suggestion: 'Shopify Access Token',
            confidence: 'high'
        },
        {
            name: 'Azure Client Secret',
            pattern: /(?:azure[_-]?client[_-]?secret|azure[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9+/]{40,})["']?/gi,
            suggestion: 'Azure Client Secret',
            confidence: 'high'
        },
        {
            name: 'Azure Subscription Key',
            pattern: /(?:azure[_-]?subscription[_-]?key|subscription[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Azure Subscription Key',
            confidence: 'high'
        },
        {
            name: 'GCP API Key',
            pattern: /(?:gcp[_-]?api[_-]?key|google[_-]?cloud[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{35,})["']?/gi,
            suggestion: 'GCP API Key',
            confidence: 'high'
        },
        {
            name: 'DigitalOcean Token',
            pattern: /dop_v1_[a-f0-9]{64}/g,
            suggestion: 'DigitalOcean Token',
            confidence: 'high'
        },
        {
            name: 'Fastly API Key',
            pattern: /(?:fastly[_-]?api[_-]?key|fastly[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Fastly API Key',
            confidence: 'high'
        },
        {
            name: 'NPM Token',
            pattern: /npm_[a-zA-Z0-9]{36}/g,
            suggestion: 'NPM Token',
            confidence: 'high'
        },
        {
            name: 'PyPI API Token',
            pattern: /pypi-[A-Za-z0-9\-_]{40,}/g,
            suggestion: 'PyPI API Token',
            confidence: 'high'
        },
        {
            name: 'Rubygems API Key',
            pattern: /(?:rubygems[_-]?api[_-]?key|rubygems[_-]?key)\s*[:=]\s*["']?([a-f0-9]{48})["']?/gi,
            suggestion: 'Rubygems API Key',
            confidence: 'high'
        },
        {
            name: 'Facebook Access Token',
            pattern: /EAAB[a-zA-Z0-9]{100,}/g,
            suggestion: 'Facebook Access Token',
            confidence: 'high'
        },
        {
            name: 'Twitter Bearer Token',
            pattern: /(?:twitter[_-]?bearer[_-]?token|bearer[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{100,})["']?/gi,
            suggestion: 'Twitter Bearer Token',
            confidence: 'high'
        },
        {
            name: 'LinkedIn API Key',
            pattern: /(?:linkedin[_-]?api[_-]?key|linkedin[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{16})["']?/gi,
            suggestion: 'LinkedIn API Key',
            confidence: 'high'
        },
        {
            name: 'Instagram Access Token',
            pattern: /(?:instagram[_-]?access[_-]?token|ig[_-]?access[_-]?token)\s*[:=]\s*["']?([0-9]{10,}\.[a-zA-Z0-9\-_]{40,})["']?/gi,
            suggestion: 'Instagram Access Token',
            confidence: 'high'
        },
        {
            name: 'Pinterest Access Token',
            pattern: /(?:pinterest[_-]?access[_-]?token|pinterest[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9\-_]{100,})["']?/gi,
            suggestion: 'Pinterest Access Token',
            confidence: 'high'
        },
        {
            name: 'PayPal Client Secret',
            pattern: /(?:paypal[_-]?client[_-]?secret|paypal[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9\-_]{50,})["']?/gi,
            suggestion: 'PayPal Client Secret',
            confidence: 'high'
        },
        {
            name: 'Square Application Secret',
            pattern: /(?:square[_-]?application[_-]?secret|square[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9\-_]{40,})["']?/gi,
            suggestion: 'Square Application Secret',
            confidence: 'high'
        },
        {
            name: 'AWS CloudFront Signed URL',
            pattern: /CloudFront-Key-Pair-Id\s*[:=]\s*["']?([A-Z0-9]{20,})["']?/gi,
            suggestion: 'AWS CloudFront Key Pair ID',
            confidence: 'high'
        },
        {
            name: 'Alibaba Cloud Access Key',
            pattern: /(?:alibaba[_-]?access[_-]?key|aliyun[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{20,})["']?/gi,
            suggestion: 'Alibaba Cloud Access Key',
            confidence: 'high'
        },
        {
            name: 'Oracle Cloud API Key',
            pattern: /(?:oracle[_-]?cloud[_-]?api[_-]?key|oci[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9+/]{40,})["']?/gi,
            suggestion: 'Oracle Cloud API Key',
            confidence: 'high'
        },
        {
            name: 'IBM Cloud API Key',
            pattern: /(?:ibm[_-]?cloud[_-]?api[_-]?key|bluemix[_-]?api[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9\-_]{40,})["']?/gi,
            suggestion: 'IBM Cloud API Key',
            confidence: 'high'
        },
        {
            name: 'Vultr API Key',
            pattern: /(?:vultr[_-]?api[_-]?key|vultr[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{64})["']?/gi,
            suggestion: 'Vultr API Key',
            confidence: 'high'
        },
        {
            name: 'Linode API Key',
            pattern: /(?:linode[_-]?api[_-]?key|linode[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{64,})["']?/gi,
            suggestion: 'Linode API Key',
            confidence: 'high'
        },
        {
            name: 'Redis Connection String',
            pattern: /redis[s]?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
            suggestion: 'Redis Connection String',
            confidence: 'high'
        },
        {
            name: 'Cassandra Connection String',
            pattern: /cassandra:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/g,
            suggestion: 'Cassandra Connection String',
            confidence: 'high'
        },
        {
            name: 'Elasticsearch Connection String',
            // eslint-disable-next-line no-useless-escape
            pattern: /(?:elasticsearch|es)[://]+[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=\-]+/g,
            suggestion: 'Elasticsearch Connection String',
            confidence: 'high'
        },
        {
            name: 'Docker Registry Password',
            pattern: /(?:docker[_-]?registry[_-]?password|docker[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{10,})["']?/gi,
            suggestion: 'Docker Registry Password',
            confidence: 'medium'
        },
        {
            name: 'Kubernetes Secret',
            pattern: /(?:kubernetes[_-]?secret|k8s[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{40,})["']?/gi,
            suggestion: 'Kubernetes Secret',
            confidence: 'medium'
        },
        {
            name: 'Terraform State Secret',
            pattern: /(?:terraform[_-]?state[_-]?secret|tf[_-]?state[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9+/=]{20,})["']?/gi,
            suggestion: 'Terraform State Secret',
            confidence: 'medium'
        },
        {
            name: 'API Key',
            pattern: /["']?(?:api[_-]?key|apikey|api_key)["']?\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
            suggestion: 'API Key',
            confidence: 'medium'
        },
        {
            name: 'Password',
            pattern: /["']?(?:password|passwd|pwd)["']?\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
            suggestion: 'Password',
            confidence: 'medium'
        },
        {
            name: 'Token',
            pattern: /["']?(?:token|auth[_-]?token|access[_-]?token|api[_-]?token|bearer[_-]?token)["']?\s*[:=]\s*["']?([a-zA-Z0-9\-_./+]{20,})["']?/gi,
            suggestion: 'Token',
            confidence: 'medium'
        },
        {
            name: 'Client Token',
            pattern: /["']?(?:client[_-]?token)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
            suggestion: 'Client Token',
            confidence: 'medium'
        },
        {
            name: 'Client Secret',
            pattern: /["']?(?:client[_-]?secret)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
            suggestion: 'Client Secret',
            confidence: 'medium'
        },
        {
            name: 'Access Token',
            pattern: /["']?(?:access[_-]?token)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
            suggestion: 'Access Token',
            confidence: 'medium'
        },
        {
            name: 'Database URL',
            pattern: /(?:database|db)[_-]?url\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
            suggestion: 'Database URL',
            confidence: 'medium'
        },
        {
            name: 'Connection String',
            pattern: /(?:connection[_-]?string|conn[_-]?string)\s*[:=]\s*["']?([^"' \t\r\n]{20,})["']?/gi,
            suggestion: 'Connection String',
            confidence: 'medium'
        },
        {
            name: 'Secret',
            pattern: /["']?(?:secret|private[_-]?key)["']?\s*[:=]\s*["']?([^"' \t\r\n]{6,})["']?/gi,
            suggestion: 'Secret',
            confidence: 'medium'
        },
        {
            name: 'Go Secret Assignment',
            pattern: /(?:secret|key|token|password)\s*[:=]\s*["']([^"']{10,})["']/gi,
            suggestion: 'Go Secret Assignment',
            confidence: 'medium'
        },
        {
            name: 'Go Function Call Secret',
            pattern: /(?:getEnv|getenv|getConfig|getSecret|getValue)\([^,)]+,\s*["']([^"']{20,})["']\)/gi,
            suggestion: 'Go Function Call Secret',
            confidence: 'medium'
        },
        
        // Cloud Provider Specific
        {
            name: 'AWS IAM Role ARN',
            pattern: /arn:aws:iam::[0-9]{12}:role\/[a-zA-Z0-9\-_]+/g,
            suggestion: 'AWS IAM Role ARN',
            confidence: 'medium'
        },
        {
            name: 'AWS S3 Bucket',
            pattern: /s3:\/\/[a-zA-Z0-9\-_]+/g,
            suggestion: 'AWS S3 Bucket',
            confidence: 'medium'
        },
        
        // Environment Variables
        {
            name: 'Environment Variable',
            pattern: /(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*[:=]\s*["']([^"']{10,})["']/g,
            suggestion: 'Environment Variable',
            confidence: 'medium'
        },
        
        // ========== ADDITIONAL PATTERNS FROM OPEN-SOURCE TOOLS ==========
        // Adding 300+ more patterns to reach 400-500+ total patterns
        
        // Additional Cloud Providers
        {
            name: 'AWS Account ID',
            pattern: /\b[0-9]{12}\b/g,
            suggestion: 'AWS Account ID',
            confidence: 'medium'
        },
        {
            name: 'AWS CloudFront Key Pair ID',
            pattern: /APKAI[0-9A-Z]{16}/g,
            suggestion: 'AWS CloudFront Key Pair ID',
            confidence: 'high'
        },
        {
            name: 'AWS MWS Auth Token',
            pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
            suggestion: 'AWS MWS Auth Token',
            confidence: 'high'
        },
        {
            name: 'Azure DevOps Personal Access Token',
            pattern: /(?:azure[_-]?devops[_-]?pat|azdo[_-]?pat)\s*[:=]\s*["']?([a-z0-9]{52})["']?/gi,
            suggestion: 'Azure DevOps PAT',
            confidence: 'high'
        },
        {
            name: 'Azure Service Bus Connection String',
            pattern: /Endpoint=sb:\/\/[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+/g,
            suggestion: 'Azure Service Bus Connection String',
            confidence: 'high'
        },
        {
            name: 'GCP OAuth Token',
            pattern: /ya29\.[a-zA-Z0-9\-_]+/g,
            suggestion: 'GCP OAuth Token',
            confidence: 'high'
        },
        {
            name: 'Google Cloud API Key',
            pattern: /AIza[0-9A-Za-z\-_]{35}/g,
            suggestion: 'Google Cloud API Key',
            confidence: 'high'
        },
        {
            name: 'Google OAuth Client Secret',
            pattern: /(?:google[_-]?oauth[_-]?client[_-]?secret|google[_-]?client[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{24,})["']?/gi,
            suggestion: 'Google OAuth Client Secret',
            confidence: 'high'
        },
        
        // Payment Processors
        {
            name: 'PayPal Client ID',
            pattern: /(?:paypal[_-]?client[_-]?id|paypal[_-]?id)\s*[:=]\s*["']?([A-Za-z0-9]{80,})["']?/gi,
            suggestion: 'PayPal Client ID',
            confidence: 'high'
        },
        {
            name: 'Braintree API Key',
            pattern: /(?:braintree[_-]?api[_-]?key|braintree[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Braintree API Key',
            confidence: 'high'
        },
        {
            name: 'Authorize.net API Key',
            pattern: /(?:authorize[_-]?net[_-]?api[_-]?key|authnet[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
            suggestion: 'Authorize.net API Key',
            confidence: 'high'
        },
        {
            name: 'Adyen API Key',
            pattern: /(?:adyen[_-]?api[_-]?key|adyen[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
            suggestion: 'Adyen API Key',
            confidence: 'high'
        },
        {
            name: 'Razorpay API Key',
            pattern: /(?:razorpay[_-]?api[_-]?key|rzp[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Razorpay API Key',
            confidence: 'high'
        },
        {
            name: '2Checkout API Key',
            pattern: /(?:2checkout[_-]?api[_-]?key|2co[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: '2Checkout API Key',
            confidence: 'high'
        },
        
        // Communication Services
        {
            name: 'Twilio Account SID',
            pattern: /AC[a-z0-9]{32}/g,
            suggestion: 'Twilio Account SID',
            confidence: 'high'
        },
        {
            name: 'Twilio Auth Token',
            pattern: /[0-9a-f]{32}/g,
            suggestion: 'Twilio Auth Token',
            confidence: 'medium'
        },
        {
            name: 'MessageBird API Key',
            pattern: /(?:messagebird[_-]?api[_-]?key|messagebird[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{25,})["']?/gi,
            suggestion: 'MessageBird API Key',
            confidence: 'high'
        },
        {
            name: 'Nexmo API Key',
            pattern: /(?:nexmo[_-]?api[_-]?key|nexmo[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{8,})["']?/gi,
            suggestion: 'Nexmo API Key',
            confidence: 'high'
        },
        {
            name: 'Nexmo API Secret',
            pattern: /(?:nexmo[_-]?api[_-]?secret|nexmo[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
            suggestion: 'Nexmo API Secret',
            confidence: 'high'
        },
        {
            name: 'Vonage API Key',
            pattern: /(?:vonage[_-]?api[_-]?key|vonage[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{8,})["']?/gi,
            suggestion: 'Vonage API Key',
            confidence: 'high'
        },
        {
            name: 'Bandwidth API Token',
            pattern: /(?:bandwidth[_-]?api[_-]?token|bandwidth[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Bandwidth API Token',
            confidence: 'high'
        },
        {
            name: 'Plivo Auth Token',
            pattern: /(?:plivo[_-]?auth[_-]?token|plivo[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'Plivo Auth Token',
            confidence: 'high'
        },
        
        // Email Services
        {
            name: 'Mailchimp API Key',
            pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g,
            suggestion: 'Mailchimp API Key',
            confidence: 'high'
        },
        {
            name: 'Mandrill API Key',
            pattern: /(?:mandrill[_-]?api[_-]?key|mandrill[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Mandrill API Key',
            confidence: 'high'
        },
        {
            name: 'Postmark API Token',
            pattern: /(?:postmark[_-]?api[_-]?token|postmark[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
            suggestion: 'Postmark API Token',
            confidence: 'high'
        },
        {
            name: 'SparkPost API Key',
            pattern: /(?:sparkpost[_-]?api[_-]?key|sparkpost[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{64,})["']?/gi,
            suggestion: 'SparkPost API Key',
            confidence: 'high'
        },
        {
            name: 'Amazon SES SMTP Password',
            pattern: /(?:amazon[_-]?ses[_-]?smtp[_-]?password|ses[_-]?smtp[_-]?password)\s*[:=]\s*["']?([A-Za-z0-9+/]{20,})["']?/gi,
            suggestion: 'Amazon SES SMTP Password',
            confidence: 'high'
        },
        {
            name: 'SendinBlue API Key',
            pattern: /(?:sendinblue[_-]?api[_-]?key|sendinblue[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'SendinBlue API Key',
            confidence: 'high'
        },
        {
            name: 'Mailjet API Key',
            pattern: /(?:mailjet[_-]?api[_-]?key|mailjet[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Mailjet API Key',
            confidence: 'high'
        },
        
        // CI/CD & DevOps
        {
            name: 'CircleCI API Token',
            pattern: /(?:circleci[_-]?api[_-]?token|circle[_-]?ci[_-]?token)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
            suggestion: 'CircleCI API Token',
            confidence: 'high'
        },
        {
            name: 'Travis CI API Token',
            pattern: /(?:travis[_-]?ci[_-]?api[_-]?token|travis[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{22})["']?/gi,
            suggestion: 'Travis CI API Token',
            confidence: 'high'
        },
        {
            name: 'Jenkins API Token',
            pattern: /(?:jenkins[_-]?api[_-]?token|jenkins[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Jenkins API Token',
            confidence: 'high'
        },
        {
            name: 'GitLab Personal Access Token',
            pattern: /glpat-[a-zA-Z0-9\-_]{20,}/g,
            suggestion: 'GitLab Personal Access Token',
            confidence: 'high'
        },
        {
            name: 'GitLab CI/CD Token',
            pattern: /(?:gitlab[_-]?ci[_-]?token|gitlab[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
            suggestion: 'GitLab CI/CD Token',
            confidence: 'high'
        },
        {
            name: 'Bitbucket App Password',
            pattern: /(?:bitbucket[_-]?app[_-]?password|bitbucket[_-]?password)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'Bitbucket App Password',
            confidence: 'high'
        },
        {
            name: 'Atlassian API Token',
            pattern: /(?:atlassian[_-]?api[_-]?token|atlassian[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
            suggestion: 'Atlassian API Token',
            confidence: 'high'
        },
        {
            name: 'Jira API Token',
            pattern: /(?:jira[_-]?api[_-]?token|jira[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
            suggestion: 'Jira API Token',
            confidence: 'high'
        },
        {
            name: 'Confluence API Token',
            pattern: /(?:confluence[_-]?api[_-]?token|confluence[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{24,})["']?/gi,
            suggestion: 'Confluence API Token',
            confidence: 'high'
        },
        {
            name: 'TeamCity API Token',
            pattern: /(?:teamcity[_-]?api[_-]?token|teamcity[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'TeamCity API Token',
            confidence: 'high'
        },
        {
            name: 'Bamboo API Token',
            pattern: /(?:bamboo[_-]?api[_-]?token|bamboo[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Bamboo API Token',
            confidence: 'high'
        },
        
        // Monitoring & Analytics
        {
            name: 'New Relic API Key',
            pattern: /(?:newrelic[_-]?api[_-]?key|new[_-]?relic[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'New Relic API Key',
            confidence: 'high'
        },
        {
            name: 'Datadog API Key',
            pattern: /(?:datadog[_-]?api[_-]?key|datadog[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Datadog API Key',
            confidence: 'high'
        },
        {
            name: 'Datadog Application Key',
            pattern: /(?:datadog[_-]?application[_-]?key|datadog[_-]?app[_-]?key)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
            suggestion: 'Datadog Application Key',
            confidence: 'high'
        },
        {
            name: 'Sentry DSN',
            pattern: /https:\/\/[a-f0-9]{32}@[a-zA-Z0-9.-]+\.ingest\.sentry\.io\/[0-9]+/g,
            suggestion: 'Sentry DSN',
            confidence: 'high'
        },
        {
            name: 'Sentry Auth Token',
            pattern: /(?:sentry[_-]?auth[_-]?token|sentry[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Sentry Auth Token',
            confidence: 'high'
        },
        {
            name: 'Rollbar Access Token',
            pattern: /(?:rollbar[_-]?access[_-]?token|rollbar[_-]?token)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Rollbar Access Token',
            confidence: 'high'
        },
        {
            name: 'Honeybadger API Key',
            // cSpell:ignore honeybadger
            pattern: /(?:honeybadger[_-]?api[_-]?key|honeybadger[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Honeybadger API Key',
            confidence: 'high'
        },
        {
            name: 'Bugsnag API Key',
            pattern: /(?:bugsnag[_-]?api[_-]?key|bugsnag[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Bugsnag API Key',
            confidence: 'high'
        },
        {
            name: 'Airbrake API Key',
            pattern: /(?:airbrake[_-]?api[_-]?key|airbrake[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Airbrake API Key',
            confidence: 'high'
        },
        {
            name: 'Mixpanel API Secret',
            pattern: /(?:mixpanel[_-]?api[_-]?secret|mixpanel[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Mixpanel API Secret',
            confidence: 'high'
        },
        {
            name: 'Segment Write Key',
            pattern: /(?:segment[_-]?write[_-]?key|segment[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Segment Write Key',
            confidence: 'high'
        },
        {
            name: 'Amplitude API Key',
            pattern: /(?:amplitude[_-]?api[_-]?key|amplitude[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Amplitude API Key',
            confidence: 'high'
        },
        {
            name: 'Google Analytics Tracking ID',
            pattern: /(?:google[_-]?analytics[_-]?tracking[_-]?id|ga[_-]?tracking[_-]?id)\s*[:=]\s*["']?(UA-[0-9]{4,10}-[0-9]{1,4})["']?/gi,
            suggestion: 'Google Analytics Tracking ID',
            confidence: 'medium'
        },
        
        // Storage & CDN
        {
            name: 'Cloudflare API Key',
            pattern: /(?:cloudflare[_-]?api[_-]?key|cloudflare[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{37})["']?/gi,
            suggestion: 'Cloudflare API Key',
            confidence: 'high'
        },
        {
            name: 'Cloudflare Global API Key',
            pattern: /(?:cloudflare[_-]?global[_-]?api[_-]?key|cf[_-]?global[_-]?key)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
            suggestion: 'Cloudflare Global API Key',
            confidence: 'high'
        },
        {
            name: 'AWS S3 Access Key',
            pattern: /(?:aws[_-]?s3[_-]?access[_-]?key|s3[_-]?access[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
            suggestion: 'AWS S3 Access Key',
            confidence: 'high'
        },
        {
            name: 'Backblaze B2 Application Key',
            pattern: /(?:backblaze[_-]?b2[_-]?application[_-]?key|b2[_-]?app[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{25})["']?/gi,
            suggestion: 'Backblaze B2 Application Key',
            confidence: 'high'
        },
        {
            name: 'DigitalOcean Spaces Access Key',
            pattern: /(?:digitalocean[_-]?spaces[_-]?access[_-]?key|do[_-]?spaces[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'DigitalOcean Spaces Access Key',
            confidence: 'high'
        },
        {
            name: 'Wasabi Access Key',
            pattern: /(?:wasabi[_-]?access[_-]?key|wasabi[_-]?key)\s*[:=]\s*["']?([A-Z0-9]{20})["']?/gi,
            suggestion: 'Wasabi Access Key',
            confidence: 'high'
        },
        
        // Database Services
        {
            name: 'Redis Password',
            pattern: /(?:redis[_-]?password|redis[_-]?pass|redis[_-]?auth)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
            suggestion: 'Redis Password',
            confidence: 'medium'
        },
        {
            name: 'Elasticsearch Password',
            pattern: /(?:elasticsearch[_-]?password|es[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
            suggestion: 'Elasticsearch Password',
            confidence: 'medium'
        },
        {
            name: 'InfluxDB Token',
            pattern: /(?:influxdb[_-]?token|influx[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
            suggestion: 'InfluxDB Token',
            confidence: 'high'
        },
        {
            name: 'CouchDB Password',
            pattern: /(?:couchdb[_-]?password|couch[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
            suggestion: 'CouchDB Password',
            confidence: 'medium'
        },
        {
            name: 'RethinkDB Password',
            pattern: /(?:rethinkdb[_-]?password|rethink[_-]?password)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
            suggestion: 'RethinkDB Password',
            confidence: 'medium'
        },
        {
            name: 'Neo4j Password',
            pattern: /(?:neo4j[_-]?password|neo4j[_-]?pass)\s*[:=]\s*["']?([^"' \t\r\n]{8,})["']?/gi,
            suggestion: 'Neo4j Password',
            confidence: 'medium'
        },
        
        // Social Media & Marketing
        {
            name: 'Facebook App Secret',
            pattern: /(?:facebook[_-]?app[_-]?secret|fb[_-]?app[_-]?secret)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Facebook App Secret',
            confidence: 'high'
        },
        {
            name: 'Twitter API Secret',
            pattern: /(?:twitter[_-]?api[_-]?secret|twitter[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Twitter API Secret',
            confidence: 'high'
        },
        {
            name: 'Twitter Consumer Key',
            pattern: /(?:twitter[_-]?consumer[_-]?key|twitter[_-]?consumer)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'Twitter Consumer Key',
            confidence: 'high'
        },
        {
            name: 'Twitter Consumer Secret',
            pattern: /(?:twitter[_-]?consumer[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Twitter Consumer Secret',
            confidence: 'high'
        },
        {
            name: 'LinkedIn Client Secret',
            pattern: /(?:linkedin[_-]?client[_-]?secret|linkedin[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{16,})["']?/gi,
            suggestion: 'LinkedIn Client Secret',
            confidence: 'high'
        },
        {
            name: 'Pinterest Client Secret',
            pattern: /(?:pinterest[_-]?client[_-]?secret|pinterest[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Pinterest Client Secret',
            confidence: 'high'
        },
        {
            name: 'Reddit Client Secret',
            pattern: /(?:reddit[_-]?client[_-]?secret|reddit[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{27,})["']?/gi,
            suggestion: 'Reddit Client Secret',
            confidence: 'high'
        },
        {
            name: 'Tumblr API Secret',
            pattern: /(?:tumblr[_-]?api[_-]?secret|tumblr[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{50,})["']?/gi,
            suggestion: 'Tumblr API Secret',
            confidence: 'high'
        },
        {
            name: 'Foursquare Client Secret',
            pattern: /(?:foursquare[_-]?client[_-]?secret|foursquare[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Foursquare Client Secret',
            confidence: 'high'
        },
        
        // Additional SaaS Services
        {
            name: 'Zendesk API Token',
            pattern: /(?:zendesk[_-]?api[_-]?token|zendesk[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Zendesk API Token',
            confidence: 'high'
        },
        {
            name: 'Intercom API Key',
            pattern: /(?:intercom[_-]?api[_-]?key|intercom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Intercom API Key',
            confidence: 'high'
        },
        {
            name: 'Freshdesk API Key',
            pattern: /(?:freshdesk[_-]?api[_-]?key|freshdesk[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Freshdesk API Key',
            confidence: 'high'
        },
        {
            name: 'Help Scout API Key',
            pattern: /(?:helpscout[_-]?api[_-]?key|help[_-]?scout[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Help Scout API Key',
            confidence: 'high'
        },
        {
            name: 'PagerDuty API Key',
            pattern: /(?:pagerduty[_-]?api[_-]?key|pagerduty[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'PagerDuty API Key',
            confidence: 'high'
        },
        {
            name: 'Opsgenie API Key',
            pattern: /(?:opsgenie[_-]?api[_-]?key|opsgenie[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'Opsgenie API Key',
            confidence: 'high'
        },
        {
            name: 'VictorOps API Key',
            pattern: /(?:victorops[_-]?api[_-]?key|victorops[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'VictorOps API Key',
            confidence: 'high'
        },
        {
            name: 'StatusPage API Key',
            pattern: /(?:statuspage[_-]?api[_-]?key|statuspage[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'StatusPage API Key',
            confidence: 'high'
        },
        {
            name: 'Pingdom API Key',
            pattern: /(?:pingdom[_-]?api[_-]?key|pingdom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Pingdom API Key',
            confidence: 'high'
        },
        {
            name: 'UptimeRobot API Key',
            pattern: /(?:uptimerobot[_-]?api[_-]?key|uptimerobot[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'UptimeRobot API Key',
            confidence: 'high'
        },
        
        // Content Management
        {
            name: 'Contentful Management Token',
            pattern: /(?:contentful[_-]?management[_-]?token|contentful[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{43})["']?/gi,
            suggestion: 'Contentful Management Token',
            confidence: 'high'
        },
        {
            name: 'Contentful Delivery Token',
            pattern: /(?:contentful[_-]?delivery[_-]?token|contentful[_-]?delivery)\s*[:=]\s*["']?([a-zA-Z0-9]{43})["']?/gi,
            suggestion: 'Contentful Delivery Token',
            confidence: 'high'
        },
        {
            name: 'Strapi API Key',
            pattern: /(?:strapi[_-]?api[_-]?key|strapi[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Strapi API Key',
            confidence: 'high'
        },
        {
            name: 'Sanity API Token',
            pattern: /(?:sanity[_-]?api[_-]?token|sanity[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Sanity API Token',
            confidence: 'high'
        },
        {
            name: 'Ghost Content API Key',
            pattern: /(?:ghost[_-]?content[_-]?api[_-]?key|ghost[_-]?api[_-]?key)\s*[:=]\s*["']?([a-f0-9]{26}:)/gi,
            suggestion: 'Ghost Content API Key',
            confidence: 'high'
        },
        {
            name: 'ButterCMS API Key',
            pattern: /(?:buttercms[_-]?api[_-]?key|butter[_-]?api[_-]?key)\s*[:=]\s*["']?([a-f0-9]{32})["']?/gi,
            suggestion: 'ButterCMS API Key',
            confidence: 'high'
        },
        
        // Search & AI Services
        {
            name: 'Algolia API Key',
            pattern: /(?:algolia[_-]?api[_-]?key|algolia[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
            suggestion: 'Algolia API Key',
            confidence: 'high'
        },
        {
            name: 'Algolia Admin API Key',
            pattern: /(?:algolia[_-]?admin[_-]?api[_-]?key|algolia[_-]?admin[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32})["']?/gi,
            suggestion: 'Algolia Admin API Key',
            confidence: 'high'
        },
        {
            name: 'Elasticsearch API Key',
            pattern: /(?:elasticsearch[_-]?api[_-]?key|es[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'Elasticsearch API Key',
            confidence: 'high'
        },
        {
            name: 'Meilisearch Master Key',
            pattern: /(?:meilisearch[_-]?master[_-]?key|meilisearch[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Meilisearch Master Key',
            confidence: 'high'
        },
        {
            name: 'Typesense API Key',
            pattern: /(?:typesense[_-]?api[_-]?key|typesense[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Typesense API Key',
            confidence: 'high'
        },
        {
            name: 'Cohere API Key',
            pattern: /(?:cohere[_-]?api[_-]?key|cohere[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Cohere API Key',
            confidence: 'high'
        },
        {
            name: 'Hugging Face API Token',
            pattern: /(?:huggingface[_-]?api[_-]?token|hf[_-]?api[_-]?token)\s*[:=]\s*["']?(hf_[a-zA-Z0-9]{37})["']?/gi,
            suggestion: 'Hugging Face API Token',
            confidence: 'high'
        },
        {
            name: 'Hugging Face Token',
            pattern: /hf_[a-zA-Z0-9]{37}/g,
            suggestion: 'Hugging Face Token',
            confidence: 'high'
        },
        {
            name: 'Replicate API Token',
            pattern: /(?:replicate[_-]?api[_-]?token|replicate[_-]?token)\s*[:=]\s*["']?(r8_[a-zA-Z0-9\-_]{37,})["']?/gi,
            suggestion: 'Replicate API Token',
            confidence: 'high'
        },
        {
            name: 'Replicate Token',
            pattern: /r8_[a-zA-Z0-9\-_]{37,}/g,
            suggestion: 'Replicate Token',
            confidence: 'high'
        },
        {
            name: 'Stability AI API Key',
            pattern: /(?:stability[_-]?ai[_-]?api[_-]?key|stability[_-]?api[_-]?key)\s*[:=]\s*["']?(sk-[a-zA-Z0-9]{48,})["']?/gi,
            suggestion: 'Stability AI API Key',
            confidence: 'high'
        },
        
        // Additional Cloud Services
        {
            name: 'Cloudinary API Secret',
            pattern: /(?:cloudinary[_-]?api[_-]?secret|cloudinary[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Cloudinary API Secret',
            confidence: 'high'
        },
        {
            name: 'ImageKit Private API Key',
            pattern: /(?:imagekit[_-]?private[_-]?api[_-]?key|imagekit[_-]?private[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'ImageKit Private API Key',
            confidence: 'high'
        },
        {
            name: 'Imgix Source Token',
            pattern: /(?:imgix[_-]?source[_-]?token|imgix[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'Imgix Source Token',
            confidence: 'high'
        },
        {
            name: 'Transloadit Auth Key',
            pattern: /(?:transloadit[_-]?auth[_-]?key|transloadit[_-]?key)\s*[:=]\s*["']?([a-f0-9]{40})["']?/gi,
            suggestion: 'Transloadit Auth Key',
            confidence: 'high'
        },
        {
            name: 'Filestack API Key',
            pattern: /(?:filestack[_-]?api[_-]?key|filestack[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{20,})["']?/gi,
            suggestion: 'Filestack API Key',
            confidence: 'high'
        },
        
        // Additional API Keys
        {
            name: 'Yelp API Key',
            pattern: /(?:yelp[_-]?api[_-]?key|yelp[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Yelp API Key',
            confidence: 'high'
        },
        {
            name: 'Foursquare API Key',
            pattern: /(?:foursquare[_-]?api[_-]?key|foursquare[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Foursquare API Key',
            confidence: 'high'
        },
        {
            name: 'Mapbox Access Token',
            pattern: /(?:mapbox[_-]?access[_-]?token|mapbox[_-]?token)\s*[:=]\s*["']?(pk\.[a-zA-Z0-9\-_]{60,})["']?/gi,
            suggestion: 'Mapbox Access Token',
            confidence: 'high'
        },
        {
            name: 'Mapbox Token',
            pattern: /pk\.[a-zA-Z0-9\-_]{60,}/g,
            suggestion: 'Mapbox Token',
            confidence: 'high'
        },
        {
            name: 'Google Maps API Key',
            pattern: /(?:google[_-]?maps[_-]?api[_-]?key|gmaps[_-]?api[_-]?key)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
            suggestion: 'Google Maps API Key',
            confidence: 'high'
        },
        {
            name: 'TomTom API Key',
            pattern: /(?:tomtom[_-]?api[_-]?key|tomtom[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'TomTom API Key',
            confidence: 'high'
        },
        {
            name: 'Here API Key',
            pattern: /(?:here[_-]?api[_-]?key|here[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{32,})["']?/gi,
            suggestion: 'Here API Key',
            confidence: 'high'
        },
        
        // Webhook & Integration Services
        {
            name: 'Webhook Secret',
            pattern: /(?:webhook[_-]?secret|webhook[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{20,})["']?/gi,
            suggestion: 'Webhook Secret',
            confidence: 'medium'
        },
        {
            name: 'Zapier Webhook Token',
            pattern: /(?:zapier[_-]?webhook[_-]?token|zapier[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Zapier Webhook Token',
            confidence: 'high'
        },
        {
            name: 'IFTTT Webhook Key',
            pattern: /(?:ifttt[_-]?webhook[_-]?key|ifttt[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'IFTTT Webhook Key',
            confidence: 'high'
        },
        {
            name: 'Microsoft Teams Webhook',
            pattern: /https:\/\/[a-zA-Z0-9.-]+\.webhook\.office\.com\/webhookb2\/[a-f0-9-]{36}@[a-f0-9-]{36}\/IncomingWebhook\/[a-f0-9-]{36}\/[a-f0-9-]{36}/g,
            suggestion: 'Microsoft Teams Webhook',
            confidence: 'high'
        },
        {
            name: 'Discord Webhook',
            pattern: /https:\/\/discord\.com\/api\/webhooks\/[0-9]{18,19}\/[a-zA-Z0-9\-_]{68}/g,
            suggestion: 'Discord Webhook',
            confidence: 'high'
        },
        {
            name: 'Slack Webhook',
            pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]{8}\/B[a-zA-Z0-9]{8}\/[a-zA-Z0-9]{24}/g,
            suggestion: 'Slack Webhook',
            confidence: 'high'
        },
        
        // Additional Security & Auth
        {
            name: 'Auth0 Management API Token',
            pattern: /(?:auth0[_-]?management[_-]?api[_-]?token|auth0[_-]?mgmt[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9\-_]{64,})["']?/gi,
            suggestion: 'Auth0 Management API Token',
            confidence: 'high'
        },
        {
            name: 'Okta API Token',
            pattern: /(?:okta[_-]?api[_-]?token|okta[_-]?token)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Okta API Token',
            confidence: 'high'
        },
        {
            name: 'OneLogin API Secret',
            pattern: /(?:onelogin[_-]?api[_-]?secret|onelogin[_-]?secret)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'OneLogin API Secret',
            confidence: 'high'
        },
        {
            name: 'Ping Identity API Key',
            pattern: /(?:ping[_-]?identity[_-]?api[_-]?key|ping[_-]?api[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{32,})["']?/gi,
            suggestion: 'Ping Identity API Key',
            confidence: 'high'
        },
        {
            name: 'Duo Secret Key',
            pattern: /(?:duo[_-]?secret[_-]?key|duo[_-]?key)\s*[:=]\s*["']?([a-zA-Z0-9]{40,})["']?/gi,
            suggestion: 'Duo Secret Key',
            confidence: 'high'
        },
        
        // Generic High-Entropy Patterns (catch-all for unknown services)
        {
            name: 'High Entropy Hex String',
            pattern: /(?:secret|key|token|password|auth)\s*[:=]\s*["']?([a-f0-9]{32,})["']?/gi,
            suggestion: 'Potential Secret (Hex)',
            confidence: 'medium'
        },
        {
            name: 'High Entropy Base64 String',
            pattern: /(?:secret|key|token|password|auth)\s*[:=]\s*["']?([A-Za-z0-9+/]{40,}={0,2})["']?/gi,
            suggestion: 'Potential Secret (Base64)',
            confidence: 'medium'
        },
        {
            name: 'Generic Long Token',
            pattern: /(?:secret|key|token|password|auth)\s*[:=]\s*["']?([a-zA-Z0-9\-_./+]{50,})["']?/gi,
            suggestion: 'Potential Long Token',
            confidence: 'medium'
        }
    ];

    private static readonly SCANNER_CONFIG = {
        // Set to true to be more lenient with development environments
        developmentMode: true,
        minEntropy: 4.0, // Increased for Go files
        // Skip common development values
        skipDevelopmentValues: true,
        // Enhanced entropy thresholds for different secret types
        entropyThresholds: {
            apiKey: 3.5, // Increased for Go files
            password: 3.0, // Increased for Go files
            token: 4.0, // Increased for Go files
            connectionString: 3.5 // Increased for Go files
        }
    };

    /**
     * Scans a document for hardcoded secrets
     */
    static async scanDocument(document: vscode.TextDocument): Promise<HardcodedSecret[]> {
        const secrets: HardcodedSecret[] = [];
        const lines = document.getText().split('\n');
        const detectedRanges: Array<{
            start: number;
            end: number;
            confidence: string;
            type: string;
        }> = [];

        for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
            const line = lines[lineIndex];
            const lineNumber = lineIndex + 1;

            // Sort patterns by confidence (high first) to prioritize better matches
            const sortedPatterns = [...this.SECRET_PATTERNS].sort((a, b) => {
                if (a.confidence === 'high' && b.confidence !== 'high') return -1;
                if (b.confidence === 'high' && a.confidence !== 'high') return 1;
                return 0;
            });

            for (const pattern of sortedPatterns) {
                let match;
                const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
                
                while ((match = regex.exec(line)) !== null) {
                    const value = match[1] || match[0]; // Use capture group if available, otherwise full match
                    
                    // Calculate the actual range of the value in the line
                    let valueStart = match.index;
                    let valueEnd = match.index + match[0].length;
                    
                    // If we have a capture group, adjust the range to the captured value
                    if (match[1]) {
                        valueStart = match.index + match[0].indexOf(match[1]);
                        valueEnd = valueStart + match[1].length;
                    }
                    
                    // Skip if it's a false positive
                    if (this.isFalsePositive(value, line, pattern)) {
                        continue;
                    }

                    // Check if this range is fully contained within an existing high-confidence detected range
                    const isContainedInHighConfidence = detectedRanges.some(range => 
                        range.confidence === 'high' && 
                        valueStart >= range.start && 
                        valueEnd <= range.end
                    );
                    
                    if (isContainedInHighConfidence) {
                        logger.debug(`Skipping ${pattern.name} "${value}" - contained within high-confidence range`);
                        continue;
                    }

                    // Add this detection to our ranges
                    detectedRanges.push({
                        start: valueStart,
                        end: valueEnd,
                        confidence: pattern.confidence,
                        type: pattern.name
                    });
                    
                    const column = valueStart + 1;
                    const context = line.trim();
                    
                    secrets.push({
                        fileName: document.fileName,
                        lineNumber,
                        column,
                        value,
                        type: pattern.suggestion,
                        context
                    });
                }
            }
        }

        return secrets;
    }

    /**
     * Scans the entire workspace for hardcoded secrets
     */
    static async scanWorkspace(): Promise<{results: Map<string, HardcodedSecret[]>, totalFilesScanned: number}> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;
        
        logger.info('Scanning current project for hardcoded secrets');
        
        // Only scan the current project files, exclude all library and build directories
        // Comprehensive file extension support for all major programming languages
        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md,go,py,java,cs,php,rb,swift,kt,rs,cpp,c,cc,h,hpp,cxx,mm,m,vue,svelte,html,css,scss,less,sass,sh,bash,zsh,fish,ps1,ps,bat,cmd,tf,tfvars,hcl,dockerfile,sql,plsql,mysql,pgsql,r,R,lua,pl,perl,vb,vbs,f,f90,f95,f03,ml,mli,fs,fsx,ex,exs,erl,hrl,nim,cr,zig,v,vala,d,jl,el,lisp,cl,hs,lhs,elm,purescript,ocaml,scala,groovy,clj,cljs,dart,asm,s,scm,rkt,coffee,litcoffee,iced,styl,stylus,jade,pug,haml,slim,ejs,hbs,handlebars,mustache,erb,rhtml,edn,re,rei,res,resi,toml,xml,xsd,xsl,xslt}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/coverage/**,**/.nyc_output/**,**/logs/**,**/temp/**,**/tmp/**,**/.venv/**,**/venv/**,**/site-packages/**,**/__pycache__/**,**/.pytest_cache/**'
        );

        logger.info(`Found ${files.length} files to scan`);

        // Scan files sequentially (simpler and more reliable)
        for (const file of files) {
            try {
                const document = await vscode.workspace.openTextDocument(file);
                const secrets = await this.scanDocument(document);
                
                if (secrets.length > 0) {
                    results.set(file.fsPath, secrets);
                    totalSecrets += secrets.length;
                    logger.debug(`Found ${secrets.length} secrets in ${vscode.workspace.asRelativePath(file.fsPath)}`);
                }
            } catch (error) {
                logger.error(`❌ Error scanning file ${file.fsPath}:`, error);
            }
        }

        logger.info(`Scan complete: Found ${totalSecrets} potential secrets in ${results.size} files`);
        return { results, totalFilesScanned: files.length };
    }

    /**
     * Scans only the current active file
     */
    static async scanCurrentFile(): Promise<{results: Map<string, HardcodedSecret[]>, totalFilesScanned: number}> {
        const results = new Map<string, HardcodedSecret[]>();
        
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            logger.info('No active editor found');
            return { results, totalFilesScanned: 0 };
        }

        logger.info(`Scanning current file: ${activeEditor.document.fileName}`);
        
        try {
            const secrets = await this.scanDocument(activeEditor.document);
            if (secrets.length > 0) {
                results.set(activeEditor.document.fileName, secrets);
                logger.info(`Found ${secrets.length} potential secrets in current file`);
            } else {
                logger.info('No secrets found in current file');
            }
        } catch (error) {
            logger.error(`❌ Error scanning current file:`, error);
        }

        return { results, totalFilesScanned: 1 };
    }

    /**
     * Scans only the current project directory (excludes libraries)
     */
    static async scanCurrentProject(): Promise<{results: Map<string, HardcodedSecret[]>, totalFilesScanned: number}> {
        const results = new Map<string, HardcodedSecret[]>();
        let totalSecrets = 0;
        
        logger.info('Scanning current project directory for hardcoded secrets');
        
        // Get the workspace root
        const workspaceRoot = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceRoot) {
            logger.error('No workspace root found');
            return { results, totalFilesScanned: 0 };
        }

        // Only scan files in the current project, exclude all library directories
        // Comprehensive file extension support for all major programming languages
        const files = await vscode.workspace.findFiles(
            '**/*.{js,jsx,ts,tsx,json,env,yml,yaml,properties,ini,cfg,conf,env.local,env.development,env.production,txt,md,go,py,java,cs,php,rb,swift,kt,rs,cpp,c,cc,h,hpp,cxx,mm,m,vue,svelte,html,css,scss,less,sass,sh,bash,zsh,fish,ps1,ps,bat,cmd,tf,tfvars,hcl,dockerfile,sql,plsql,mysql,pgsql,r,R,lua,pl,perl,vb,vbs,f,f90,f95,f03,ml,mli,fs,fsx,ex,exs,erl,hrl,nim,cr,zig,v,vala,d,jl,el,lisp,cl,hs,lhs,elm,purescript,ocaml,scala,groovy,clj,cljs,dart,asm,s,scm,rkt,coffee,litcoffee,iced,styl,stylus,jade,pug,haml,slim,ejs,hbs,handlebars,mustache,erb,rhtml,edn,re,rei,res,resi,toml,xml,xsd,xsl,xslt}',
            '**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**,**/.nyc_output/**,**/vendor/**,**/out/**,**/target/**,**/bin/**,**/obj/**,**/.vscode-test/**,**/logs/**,**/temp/**,**/tmp/**,**/.venv/**,**/venv/**,**/site-packages/**,**/__pycache__/**,**/.pytest_cache/**,**/package-lock.json,**/yarn.lock'
        );

        // Additional filter to exclude node_modules and other library files
        const filteredFiles = files.filter(file => {
            const filePath = file.fsPath.toLowerCase();
            const shouldExclude = filePath.includes('node_modules') || 
                   filePath.includes('dist') || 
                   filePath.includes('build') || 
                   filePath.includes('.git') || 
                   filePath.includes('coverage') || 
                   filePath.includes('vendor') || 
                   filePath.includes('out') || 
                   filePath.includes('target') || 
                   filePath.includes('bin') || 
                   filePath.includes('obj') || 
                   filePath.includes('.vscode-test') || 
                   filePath.includes('logs') || 
                   filePath.includes('temp') || 
                   filePath.includes('tmp') ||
                   filePath.includes('.venv') ||
                   filePath.includes('venv/') ||
                   filePath.includes('site-packages') ||
                   filePath.includes('__pycache__') ||
                   filePath.includes('.pytest_cache') ||
                   filePath.endsWith('package-lock.json') ||
                   filePath.endsWith('yarn.lock');
            
            if (shouldExclude) {
                logger.debug(`Excluding library file: ${vscode.workspace.asRelativePath(file.fsPath)}`);
            }
            
            return !shouldExclude;
        });

        logger.info(`Found ${files.length} total files, filtered to ${filteredFiles.length} project files to scan`);

        // Scan files sequentially
        for (const file of filteredFiles) {
            try {
                const document = await vscode.workspace.openTextDocument(file);
                const secrets = await this.scanDocument(document);
                
                if (secrets.length > 0) {
                    results.set(file.fsPath, secrets);
                    totalSecrets += secrets.length;
                    logger.debug(`Found ${secrets.length} secrets in ${vscode.workspace.asRelativePath(file.fsPath)}`);
                }
            } catch (error) {
                logger.error(`❌ Error scanning file ${file.fsPath}:`, error);
            }
        }

        logger.info(`Project scan complete: Found ${totalSecrets} potential secrets in ${results.size} files`);
        return { results, totalFilesScanned: filteredFiles.length };
    }

    /**
     * Configures the scanner behavior
     */
    static configure(options: {
        developmentMode?: boolean;
        minEntropy?: number;
        skipDevelopmentValues?: boolean;
    }): void {
        if (options.developmentMode !== undefined) {
            this.SCANNER_CONFIG.developmentMode = options.developmentMode;
        }
        if (options.minEntropy !== undefined) {
            this.SCANNER_CONFIG.minEntropy = options.minEntropy;
        }
        if (options.skipDevelopmentValues !== undefined) {
            this.SCANNER_CONFIG.skipDevelopmentValues = options.skipDevelopmentValues;
        }
        
        logger.info('Scanner configuration updated:', this.SCANNER_CONFIG);
    }


    /**
     * Calculates entropy of a string (measure of randomness)
     */
    private static calculateEntropy(str: string): number {
        if (!str || str.length === 0) return 0;
        
        const charCounts = new Map<string, number>();
        for (const char of str) {
            charCounts.set(char, (charCounts.get(char) || 0) + 1);
        }
        
        let entropy = 0;
        const length = str.length;
        
        for (const count of charCounts.values()) {
            const probability = count / length;
            entropy -= probability * Math.log2(probability);
        }
        
        // Consider character set diversity
        const uniqueChars = charCounts.size;
        const maxPossibleChars = 95; // Printable ASCII characters
        const diversityBonus = Math.min(uniqueChars / maxPossibleChars, 1) * 0.5;
        
        // Length bonus for longer strings
        const lengthBonus = Math.min(str.length / 50, 1) * 0.3;
        
        return entropy + diversityBonus + lengthBonus;
    }

    /**
     * Checks if a detected value is a false positive using sophisticated analysis
     */
    private static isFalsePositive(value: string, line: string, pattern?: any): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        
        // Apply stricter filtering for Go files
        const isGoFile = line.includes('.go') || lowerLine.includes('package ') || 
                        lowerLine.includes('import ') || lowerLine.includes('func ') ||
                        lowerLine.includes('var ') || lowerLine.includes('const ') ||
                        lowerLine.includes('type ') || lowerLine.includes('struct ') ||
                        lowerLine.includes('interface ') || lowerLine.includes('fmt.') ||
                        lowerLine.includes('log.') || lowerLine.includes('http.') ||
                        lowerLine.includes('mux.') || lowerLine.includes('gin.') ||
                        lowerLine.includes('echo.') || lowerLine.includes('fiber.');
        
        // Skip JSON schema references early (common false positive)
        if (value.includes('$ref') || value.includes('#/$defs') || value.includes('#/definitions') ||
            value.startsWith('#/') || (value.startsWith('$') && !value.includes('='))) {
            logger.debug(`Filtered JSON schema reference: "${value}"`);
            return true;
        }
        
        // Skip file paths and bundle names early (common false positive)
        if (value.includes('.js') || value.includes('.ts') || 
            value.includes('main-') || value.includes('bundle-') || value.includes('chunk-') ||
            value.match(/^[a-zA-Z0-9_-]+\.(js|ts|jsx|tsx|json|css|html|png|jpg|jpeg|gif|svg)$/i)) {
            
            // If it has path separators or looks like a filename, filter it
            if (value.includes('/') || value.includes('\\') || value.match(/\.[a-z0-9]{2,4}$/i)) {
                logger.debug(`Filtered file path/bundle name: "${value}"`);
                return true;
            }
        }
        
        // Skip JSON schema property names in schema context
        if ((value.includes('Config') || value.includes('AuthConfig') || value.includes('ServiceAccount')) && 
            (lowerLine.includes('$ref') || lowerLine.includes('#/$defs') || lowerLine.includes('#/definitions') ||
            lowerLine.includes('"type"') || lowerLine.includes('"properties"') ||
            lowerLine.includes('"description"') || lowerLine.includes('"required"') ||
            lowerLine.includes('"$defs"') || lowerLine.includes('"definitions"'))) {
            logger.debug(`Filtered JSON schema property: "${value}"`);
            return true;
        }
        
        // Skip values that are clearly type names or class names (PascalCase with Config/Account/etc.)
        if (value.match(/^[A-Z][a-zA-Z0-9]*(Config|Account|Service|Provider|Client|Manager|Handler|Controller)[a-zA-Z0-9]*$/) &&
            (lowerLine.includes('"type"') || lowerLine.includes('"$ref"') || lowerLine.includes('"class"'))) {
            logger.debug(`Filtered type/class name: "${value}"`);
            return true;
        }
        
        if (pattern && pattern.confidence === 'high') {
            // Only filter high confidence patterns if they're clearly false positives
            if (this.isClearlyFalsePositive(value, line)) {
                logger.debug(`Filtered high-confidence pattern "${pattern.name}": "${value}"`);
                return true;
            }
            return false;
        }
        

        if (pattern && pattern.confidence === 'medium') {
            const entropy = this.calculateEntropy(value);
            
            // Get specific threshold based on pattern type
            let threshold = this.SCANNER_CONFIG.minEntropy;
            if (pattern.name.toLowerCase().includes('api')) {
                threshold = this.SCANNER_CONFIG.entropyThresholds.apiKey;
            } else if (pattern.name.toLowerCase().includes('password')) {
                threshold = this.SCANNER_CONFIG.entropyThresholds.password;
            } else if (pattern.name.toLowerCase().includes('token')) {
                // For tokens, use a more lenient threshold - tokens can have various formats
                // and high-entropy alphanumeric strings with hyphens/underscores are likely real tokens
                threshold = Math.min(this.SCANNER_CONFIG.entropyThresholds.token, 3.5);
                // If token is 30+ chars and contains alphanumeric with separators, it's likely real
                if (value.length >= 30 && /^[a-zA-Z0-9\-_./+]+$/.test(value)) {
                    threshold = 3.0; // Lower threshold for longer, well-formed tokens
                }
            } else if (pattern.name.toLowerCase().includes('connection')) {
                threshold = this.SCANNER_CONFIG.entropyThresholds.connectionString;
            }
            
            // For shorter secrets (client_token, client_secret, access_token), use lower threshold
            if (pattern.name.toLowerCase().includes('client') && value.length < 15) {
                threshold = 2.0; // Lower threshold for shorter client tokens/secrets
            }
            
            // Apply stricter filtering for Go files
            if (isGoFile) {
                threshold += 0.5; // Increase threshold for Go files
            }
            
            // Low entropy indicates it's likely not a real secret
            // But allow very short values if they match specific patterns (like client_token, client_secret)
            if (entropy < threshold && !(pattern.name.toLowerCase().includes('client') && value.length < 15)) {
                logger.debug(`Filtered by low entropy (${entropy.toFixed(2)} < ${threshold}): "${value}"`);
                return true;
            }
        }
        
        // Skip if contains common false positive keywords
        if (lowerValue.includes('example') || lowerValue.includes('dummy') || 
            lowerValue.includes('placeholder') || lowerValue.includes('sample') ||
            lowerValue.includes('your-') || lowerValue.includes('your_') ||
            lowerValue.includes('replace-') || lowerValue.includes('replace_') ||
            lowerValue.includes('add-') || lowerValue.includes('add_')) {
            logger.debug(`Filtered by false positive keyword: "${value}"`);
            return true;
        }
        
        // Only skip 'test' if it's clearly a test pattern, not if it's part of a real key
        if (lowerValue === 'test' || lowerValue === 'testing') {
            logger.debug(`Filtered by test keyword: "${value}"`);
            return true;
        }
        
        // Skip common HTTP headers and content types
        if (lowerValue.includes('application/json') || lowerValue.includes('application/xml') || 
            lowerValue.includes('text/html') || lowerValue.includes('text/plain') ||
            lowerValue.includes('multipart/form-data') || lowerValue.includes('application/x-www-form-urlencoded')) {
            logger.debug(`Filtered by content type: "${value}"`);
            return true;
        }
        
        // Skip common MIME types
        if (lowerValue.includes('image/') || lowerValue.includes('video/') || lowerValue.includes('audio/')) {
            logger.debug(`Filtered by MIME type: "${value}"`);
            return true;
        }
        
        // Skip common HTTP methods
        if (lowerValue === 'get' || lowerValue === 'post' || lowerValue === 'put' || 
            lowerValue === 'delete' || lowerValue === 'patch') {
            logger.debug(`Filtered by HTTP method: "${value}"`);
            return true;
        }
        
        // Skip common HTTP status codes
        if (lowerValue === '200' || lowerValue === '201' || lowerValue === '400' || 
            lowerValue === '401' || lowerValue === '403' || lowerValue === '404' || 
            lowerValue === '500' || lowerValue === '502' || lowerValue === '503') {
            logger.debug(`Filtered by HTTP status code: "${value}"`);
            return true;
        }
        
        // Skip common file extensions and paths
        if (lowerValue.includes('.js') || lowerValue.includes('.ts') || lowerValue.includes('.jsx') || 
            lowerValue.includes('.tsx') || lowerValue.includes('.json') || lowerValue.includes('.css') ||
            lowerValue.includes('.html') || lowerValue.includes('.svg') || lowerValue.includes('.png') ||
            lowerValue.includes('.jpg') || lowerValue.includes('.jpeg') || lowerValue.includes('.gif') ||
            lowerValue.includes('/bin/') || lowerValue.includes('/dist/') || lowerValue.includes('/node_modules/') ||
            lowerValue.includes('/src/') || lowerValue.includes('/build/') || lowerValue.includes('/public/')) {
            logger.debug(`Filtered by file extension/path: "${value}"`);
            return true;
        }
        
        // Skip common programming terms and build tools
        if (lowerValue.includes('function') || lowerValue.includes('const') || lowerValue.includes('let') ||
            lowerValue.includes('var') || lowerValue.includes('return') || lowerValue.includes('import') ||
            lowerValue.includes('export') || lowerValue.includes('default') || lowerValue.includes('async') ||
            lowerValue.includes('await') || lowerValue.includes('try') || lowerValue.includes('catch') ||
            lowerValue.includes('rollup') || lowerValue.includes('autoprefixer') || lowerValue.includes('webpack') ||
            lowerValue.includes('babel') || lowerValue.includes('eslint') || lowerValue.includes('prettier') ||
            lowerValue.includes('jest') || lowerValue.includes('mocha') || lowerValue.includes('chai')) {
            logger.debug(`Filtered by programming term: "${value}"`);
            return true;
        }
        
        // Go-specific false positives
        if (lowerValue.includes('.') && (lowerValue.includes('request') || lowerValue.includes('response') ||
            lowerValue.includes('finding') || lowerValue.includes('extrafields') || lowerValue.includes('addr') ||
            lowerValue.includes('http') || lowerValue.includes('service') || lowerValue.includes('session') ||
            lowerValue.includes('context') || lowerValue.includes('error') || lowerValue.includes('result') ||
            lowerValue.includes('data') || lowerValue.includes('config') || lowerValue.includes('client') ||
            lowerValue.includes('server') || lowerValue.includes('handler') || lowerValue.includes('router') ||
            lowerValue.includes('middleware') || lowerValue.includes('database') || lowerValue.includes('store') ||
            lowerValue.includes('model') || lowerValue.includes('struct') || lowerValue.includes('interface'))) {
            logger.debug(`Filtered by Go struct field access: "${value}"`);
            return true;
        }
        
        // Skip Go package imports and struct field access patterns
        if (value.includes('.') && !value.includes('=') && !value.includes(':') && 
            (value.match(/^[A-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) || 
             value.match(/^[a-z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) ||
             value.match(/^[a-z][a-zA-Z0-9]*\.[a-z][a-zA-Z0-9]*/))) {
            logger.debug(`Filtered by Go package/struct pattern: "${value}"`);
            return true;
        }
        
        // Don't filter out JWT tokens (they contain dots but are valid secrets)
        if (value.startsWith('eyJ') && value.includes('.') && value.length > 50) {
            logger.debug(`Not filtering JWT token: "${value}"`);
            return false;
        }
        
        // IMPROVED: Better development vs production detection
        if (this.SCANNER_CONFIG.skipDevelopmentValues && this.isDevelopmentValue(value, line)) {
            logger.debug(`Filtered by development value: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: Markdown files often contain documentation and examples
        if (pattern && pattern.confidence === 'medium' && 
            (lowerValue.includes('your-') || lowerValue.includes('your_') || 
             lowerValue.includes('example-') || lowerValue.includes('example_') ||
             lowerValue.includes('sample-') || lowerValue.includes('sample_') ||
             lowerValue.includes('placeholder-') || lowerValue.includes('placeholder_'))) {
            logger.debug(`Filtered example value in documentation: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: AWS Session Token handling
        // If this is an AWS Secret Key pattern and the line contains SESSION_TOKEN,
        // and the value is exactly 40 characters, it's likely a substring of the session token
        if (pattern && pattern.name === 'AWS Secret Key' && 
            lowerLine.includes('session_token') && value.length === 40) {
            logger.debug(`Filtered AWS Secret Key as part of AWS Session Token: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: Very long tokens (likely session tokens) should not be matched by generic patterns
        if (pattern && pattern.confidence === 'medium' && value.length > 200) {
            logger.debug(`Filtered very long token by generic pattern: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: Environment variable names (not actual secrets)
        if (value.includes('_') && value === value.toUpperCase() && 
            (value.includes('AWS_') || value.includes('GCP_') || value.includes('AZURE_') || 
             value.includes('DATABASE_') || value.includes('API_') || value.includes('SECRET_'))) {
            logger.debug(`Filtered environment variable name: "${value}"`);
            return true;
        }
        
        // SPECIAL CASE: README files often contain example values
        if (pattern && pattern.confidence === 'medium' && 
            (lowerValue.includes('your-') || lowerValue.includes('your_') || 
             lowerValue.includes('example-') || lowerValue.includes('example_') ||
             lowerValue.includes('sample-') || lowerValue.includes('sample_'))) {
            logger.debug(`Filtered example value in README: "${value}"`);
            return true;
        }
        
        // Skip if it's clearly not a secret (too short, too simple, or just common words)
        // But allow shorter values for client_token, client_secret, access_token patterns
        const isClientPattern = pattern && (pattern.name.toLowerCase().includes('client') || 
                                           pattern.name.toLowerCase().includes('access_token'));
        const minLength = isClientPattern ? 6 : 10;
        
        if (value.length < minLength || /^[a-z]+$/i.test(value) || 
            lowerValue.includes('true') || lowerValue.includes('false') || lowerValue.includes('null') ||
            lowerValue.includes('undefined') || lowerValue.includes('nan')) {
            logger.debug(`Filtered by simple value: "${value}"`);
            return true;
        }
        
        return false;
    }

    /**
     * NEW: Checks if a value is likely a development/test value
     */
    private static isDevelopmentValue(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        
        // Skip common development passwords
        if (lowerValue === 'password' || lowerValue === 'pass' || lowerValue === 'pwd' ||
            lowerValue === 'admin' || lowerValue === 'root' || lowerValue === 'user' ||
            lowerValue === 'test' || lowerValue === 'demo' || lowerValue === 'dev' ||
            lowerValue === 'development' || lowerValue === 'staging') {
            return true;
        }
        
        // Skip localhost URLs and common dev ports
        if (lowerValue.includes('localhost') || lowerValue.includes('127.0.0.1') ||
            lowerValue.includes(':3000') || lowerValue.includes(':8080') || 
            lowerValue.includes(':5432') || lowerValue.includes(':27017') ||
            lowerValue.includes(':6379') || lowerValue.includes(':7687')) {
            return true;
        }
        
        // Skip common development database credentials
        if (lowerValue === 'neo4j' || lowerValue === 'postgres' || lowerValue === 'mysql' ||
            lowerValue === 'mongodb' || lowerValue === 'redis') {
            return true;
        }
        
        // Skip if the line contains development indicators
        if (lowerLine.includes('debug') || lowerLine.includes('development') || 
            lowerLine.includes('staging') || lowerLine.includes('test') ||
            lowerLine.includes('optional') || lowerLine.includes('local')) {
            return true;
        }
        
        // Go-specific development patterns
        if (lowerLine.includes('fmt.printf') || lowerLine.includes('log.printf') || 
            lowerLine.includes('fmt.fprintf') || lowerLine.includes('log.fatal') ||
            lowerLine.includes('http.handlefunc') || lowerLine.includes('mux.handlefunc') ||
            lowerLine.includes('func(') || lowerLine.includes('return') ||
            lowerLine.includes('if ') || lowerLine.includes('for ') || lowerLine.includes('switch ') ||
            lowerLine.includes('case ') || lowerLine.includes('default:') ||
            lowerLine.includes('var ') || lowerValue.includes('const ') ||
            lowerLine.includes('type ') || lowerLine.includes('struct ') ||
            lowerLine.includes('interface ') || lowerLine.includes('package ')) {
            return true;
        }
        
        // Skip if it's a simple boolean or common dev value
        if (lowerValue === 'true' || lowerValue === 'false' || lowerValue === 'yes' || 
            lowerValue === 'no' || lowerValue === 'on' || lowerValue === 'off') {
            return true;
        }
        
        return false;
    }

    /**
     * Checks if a high-confidence pattern is clearly a false positive
     */
    private static isClearlyFalsePositive(value: string, line: string): boolean {
        const lowerValue = value.toLowerCase();
        const lowerLine = line.toLowerCase();
        
        // Skip JSON schema references ($ref, #/$defs, etc.)
        if (value.includes('$ref') || value.includes('#/$defs') || value.includes('#/definitions') ||
            value.startsWith('#/') || value.startsWith('$')) {
            return true;
        }
        
        // Skip file paths and bundle names (common in JS bundles)
        if (value.includes('/') && (value.includes('.js') || value.includes('.ts') || 
            value.includes('main-') || value.includes('bundle-') || value.includes('chunk-'))) {
            return true;
        }
        
        // Skip if it looks like a filename or path
        if (value.match(/^[a-zA-Z0-9_-]+\.(js|ts|jsx|tsx|json|css|html|png|jpg|jpeg|gif|svg)$/i)) {
            return true;
        }
        
        // Skip if contains common false positive keywords
        if (lowerValue.includes('example') || lowerValue.includes('dummy') || 
            lowerValue.includes('placeholder') || lowerValue.includes('sample')) {
            return true;
        }
        
        // Skip if it's clearly a test or example
        if (lowerValue === 'test' || lowerValue === 'testing' || lowerValue === 'example') {
            return true;
        }
        
        // Skip common HTTP headers and content types
        if (lowerValue.includes('application/json') || lowerValue.includes('application/xml') || 
            lowerValue.includes('text/html') || lowerValue.includes('text/plain')) {
            return true;
        }
        
        // Skip if it's clearly not a secret (too short or simple)
        if (value.length < 10 || /^[a-z]+$/i.test(value)) {
            return true;
        }
        
        // Skip Go struct field access patterns (e.g., "finding.Finding.ExtraFields")
        if (value.includes('.') && !value.includes('=') && !value.includes(':') && 
            (value.match(/^[a-zA-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/) ||
             value.match(/^[a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]*\.[A-Z][a-zA-Z0-9]*/))) {
            return true;
        }
        
        // Skip JSON schema property names and type definitions
        if (value.includes('Config') && (value.includes('AuthConfig') || value.includes('ServiceAccount') ||
            value.includes('Google') || value.includes('Azure') || value.includes('AWS'))) {
            // Check if it's in a JSON schema context
            if (lowerLine.includes('$ref') || lowerLine.includes('#/$defs') || 
                lowerLine.includes('"type"') || lowerLine.includes('"properties"')) {
                return true;
            }
        }
        
        // Don't filter out JWT tokens (they contain dots but are valid secrets)
        if (value.startsWith('eyJ') && value.includes('.') && value.length > 50) {
            return false;
        }
        
        return false;
    }

    /**
     * Generates a suggested name for a secret based on its context
     */
    static generateSecretName(secret: HardcodedSecret, fileName: string): string {
        const baseName = fileName.split('/').pop()?.replace(/\.[^/.]+$/, '') || 'unknown';
        const timestamp = Date.now();
        
        // Try to extract a meaningful name from the context
        const contextLower = secret.context.toLowerCase();
        let type = 'secret';
        
        if (contextLower.includes('api') || contextLower.includes('key')) {
            type = 'api-key';
        } else if (contextLower.includes('password') || contextLower.includes('passwd')) {
            type = 'password';
        } else if (contextLower.includes('token')) {
            type = 'token';
        } else if (contextLower.includes('database') || contextLower.includes('db')) {
            type = 'database-url';
        }
        
        return `/secrets/${baseName}-${type}-${timestamp}`;
    }
} 