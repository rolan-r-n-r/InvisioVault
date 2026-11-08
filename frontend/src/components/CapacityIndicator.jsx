import { useState, useEffect } from 'react'
import { AlertCircle, AlertTriangle, Activity, CheckCircle2, BarChart3, Info } from 'lucide-react'
import axios from 'axios'
import './CapacityIndicator.css'
import API_URL from '../config/api'

function CapacityIndicator({ carrierFile, hiddenFile, hiddenText, mode = 'stego', password, engine = 'v6' }) {
    const [capacity, setCapacity] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    // Calculate file size with accurate overhead
    const calculateUsedBytes = (file, text, hasPassword, currentEngine) => {
        let metadataSize = 0
        let dataSize = 0
        let isPreCompressed = false

        if (file) {
            const mimeType = file.type || 'application/octet-stream'
            metadataSize = (file.name + '|' + mimeType).length
            dataSize = file.size
            const ext = (file.name.split('.').pop() || '').toLowerCase()
            const preCompressedExts = ['zip', 'apk', 'png', 'jpg', 'jpeg', 'webp', 'mp4', 'pdf', 'docx', 'xlsx', 'gz', '7z', 'rar', 'bz2']
            if (preCompressedExts.includes(ext)) {
                isPreCompressed = true
            }
        } else if (text) {
            metadataSize = ('hidden_text.txt|text/plain').length
            dataSize = new Blob([text]).size
        }

        // Realistic compression estimation:
        // Pre-compressed files do not compress further (1.0x).
        // Text compresses well (~0.4x). General uncompressed files ~0.7x.
        let estimatedCompressedSize = dataSize
        if (text) {
            estimatedCompressedSize = Math.ceil(dataSize * 0.4)
        } else if (!isPreCompressed) {
            estimatedCompressedSize = Math.ceil(dataSize * 0.7)
        }

        if (currentEngine === 'v6') {
            // V6 engine uses JSON framing + Fernet/CRC.
            // Raw pre-RS capacity is compared directly against max_raw_payload_capacity.
            const cryptoOverhead = hasPassword ? 60 : 4
            const v6MetadataOverhead = 100 // JSON metadata overhead
            return estimatedCompressedSize + v6MetadataOverhead + cryptoOverhead + 2
        }

        // Cryptographic overhead: Fernet binary token adds ~60 bytes (IV, timestamp, HMAC, padding).
        // Encrypted metadata also has Fernet token overhead (~120 bytes).
        const cryptoOverhead = hasPassword ? 60 : 0
        const encMetadataSize = hasPassword ? Math.max(metadataSize + 70, 120) : metadataSize

        // Channel coding (Reed-Solomon RS(255, 223)) overhead:
        // Adds 32 parity bytes per 223-byte block (~14.3% expansion).
        const payloadBeforeECC = estimatedCompressedSize + cryptoOverhead
        const eccParityBytes = Math.ceil(payloadBeforeECC / 223) * 32
        const totalPayloadWithECC = payloadBeforeECC + eccParityBytes

        // Header: MAGIC(2) + flag(1) + salt(16) + meta_len(4) + metadata + data_len(4) + threshold(1) = 28 + metadata
        const headerSize = 28 + encMetadataSize

        return headerSize + totalPayloadWithECC
    }

    // Format bytes to human-readable string
    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 Bytes'
        if (bytes < 1024) return `${bytes} Bytes`
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    }

    // Get status based on percentage
    const getStatus = (percentage) => {
        // Determine if we're hiding text or a file
        const contentType = hiddenText ? 'Text' : 'File'

        if (percentage > 100) {
            return {
                level: 'error',
                icon: <AlertCircle size={18} />,
                message: `${contentType} is too large for this image`
            }
        } else if (percentage > 90) {
            return {
                level: 'warning',
                icon: <AlertTriangle size={18} />,
                message: `${contentType} will barely fit - consider using a larger image`
            }
        } else if (percentage > 70) {
            return {
                level: 'caution',
                icon: <Activity size={18} />,
                message: `${contentType} will fit, but capacity is high`
            }
        } else {
            return {
                level: 'success',
                icon: <CheckCircle2 size={18} />,
                message: `${contentType} will fit comfortably`
            }
        }
    }

    useEffect(() => {
        // AbortController lets us cancel the in-flight request when:
        //   - the user swaps files before the previous request finishes, or
        //   - the component unmounts mid-request.
        const controller = new AbortController()

        const calculateCapacity = async () => {
            if (!carrierFile) {
                setCapacity(null)
                return
            }

            setLoading(true)
            setError('')

            try {
                // Get total capacity from backend
                const formData = new FormData()
                formData.append('image', carrierFile)
                formData.append('engine', engine)

                const endpoint = engine === 'v6' ? `${API_URL}/api/calculate-capacity-v6` : `${API_URL}/api/calculate-capacity`
                const response = await axios.post(endpoint, formData, {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    },
                    // Cancel this request if the user changes files or the
                    // component unmounts before the server responds.
                    signal: controller.signal,
                    // Hard timeout: if the backend is cold/unreachable, give up
                    // after 15 s instead of hanging forever.
                    timeout: 15000
                })

                const totalBytes = response.data.totalCapacityBytes

                // Calculate used bytes
                const usedBytes = calculateUsedBytes(hiddenFile, hiddenText, !!password, engine)
                const percentage = totalBytes > 0 ? Math.round((usedBytes / totalBytes) * 100) : 100

                setCapacity({
                    totalBytes,
                    usedBytes,
                    percentage,
                    totalFormatted: formatBytes(totalBytes),
                    usedFormatted: formatBytes(usedBytes)
                })
            } catch (err) {
                // Ignore cancellation errors — they are intentional cleanup,
                // not real failures (e.g. user picked a different file).
                if (axios.isCancel(err) || err.name === 'CanceledError') return

                if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
                    setError('Server is taking too long to respond. Please try again.')
                } else {
                    setError(err.response?.data?.error || 'Failed to calculate capacity')
                }
            } finally {
                // Only clear the spinner if this request was NOT cancelled.
                // If it was cancelled a new request is already on the way.
                if (!controller.signal.aborted) {
                    setLoading(false)
                }
            }
        }

        // Debounce the capacity calculation to prevent excessive API calls
        const timeoutId = setTimeout(() => {
            calculateCapacity()
        }, 500) // 500ms delay

        return () => {
            clearTimeout(timeoutId)
            // Cancel the in-flight HTTP request so it doesn't setState on an
            // unmounted component or clobber a newer request's result.
            controller.abort()
        }
    }, [carrierFile, hiddenFile, hiddenText, password, mode, engine])

    if (!carrierFile || (!hiddenFile && !hiddenText)) {
        return null
    }

    if (loading) {
        return (
            <div className="capacity-indicator loading" role="status" aria-live="polite">
                <div className="capacity-spinner" aria-hidden="true"></div>
                <p>Calculating capacity...</p>
            </div>
        )
    }

    if (error) {
        return (
            <div className="capacity-indicator error" role="alert">
                <p style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <AlertTriangle size={16} aria-hidden="true" />
                    <span>{error}</span>
                </p>
            </div>
        )
    }

    if (!capacity) {
        return null
    }

    const status = getStatus(capacity.percentage)
    const progressWidth = Math.min(capacity.percentage, 100)

    return (
        <div className={`capacity-indicator ${status.level}`}>
            <div className="capacity-header">
                <h4>
                    <BarChart3 size={18} aria-hidden="true" />
                    <span>Capacity Analysis</span>
                </h4>
            </div>

            <div className="capacity-stats">
                <div className="stat">
                    <span className="stat-label">Image Capacity:</span>
                    <span className="stat-value">{capacity.totalFormatted}</span>
                </div>
                <div className="stat">
                    <span className="stat-label">{hiddenText ? 'Text Size' : 'File Size'} (estimated):</span>
                    <span className="stat-value">{capacity.usedFormatted}</span>
                </div>
            </div>

            <div className="progress-container">
                <div
                    className="progress-bar"
                    role="progressbar"
                    aria-valuenow={Math.min(Math.max(capacity.percentage, 0), 100)}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuetext={`${capacity.percentage}% capacity used`}
                    aria-label="Image steganography capacity used"
                >
                    <div
                        className={`progress-fill ${status.level}`}
                        style={{ width: `${progressWidth}%` }}
                    >
                        <div className="progress-shine" aria-hidden="true"></div>
                    </div>
                </div>
                <div className="progress-label" aria-hidden="true">
                    {capacity.percentage}% capacity used
                </div>
            </div>

            <div className={`status-message ${status.level}`} role="status" aria-live="polite">
                <span className="status-icon" aria-hidden="true">{status.icon}</span>
                <span className="status-text">{status.message}</span>
            </div>

            {mode === 'stego' && (
                <div className="capacity-note">
                    <small style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <Info size={14} style={{ flexShrink: 0 }} aria-hidden="true" />
                        <span>
                            Capacity based on LSB steganography (3 bits per pixel).
                            {password && ' Encryption adds ~16 bytes overhead.'}
                        </span>
                    </small>
                </div>
            )}
        </div>
    )
}

export default CapacityIndicator
