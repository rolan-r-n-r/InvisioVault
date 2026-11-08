import { useState, useMemo } from 'react'
import { FileText, Type, Lock, AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, CheckCircle2, Download, Eye, EyeOff, Cpu } from 'lucide-react'
import axios from 'axios'
import './HideFile.css'
import API_URL from '../config/api'
import { getApiErrorMessage } from '../utils/apiError'
import CapacityIndicator from './CapacityIndicator'
import FileDropzone from './FileDropzone'
import StepProgress from './StepProgress'
import ProcessingIndicator from './ProcessingIndicator'

const STEPS = [
  { id: 1, label: 'Carrier Image' },
  { id: 2, label: 'Secret Payload' },
  { id: 3, label: 'Security & Config' },
  { id: 4, label: 'Generate & Download' }
]

function HideFile() {
  const [v6Mode, setV6Mode] = useState('encrypted') // 'encrypted' or 'plain'
  const [mode, setMode] = useState('file') // 'file' or 'text'
  const [image, setImage] = useState(null)
  const [file, setFile] = useState(null)
  const [text, setText] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [passwordError, setPasswordError] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [downloadId, setDownloadId] = useState('')
  const [downloading, setDownloading] = useState(false)

  const MIN_PASSWORD_LENGTH = 8

  const hasActivePayload = mode === 'file' ? Boolean(file) : Boolean(text.trim())

  const handleModeChange = (newMode) => {
    setMode(newMode)
    setError('')
  }

  const getCurrentStep = () => {
    if (success || loading) return 4
    if (image && hasActivePayload) return 3
    if (image) return 2
    return 1
  }

  const getPasswordStrength = (pwd) => {
    const trimmed = pwd?.trim()
    if (!trimmed) return null
    if (trimmed.length < MIN_PASSWORD_LENGTH) return 'weak'
    const hasUpper = /[A-Z]/.test(trimmed)
    const hasLower = /[a-z]/.test(trimmed)
    const hasDigit = /\d/.test(trimmed)
    const hasSpecial = /[^A-Za-z0-9]/.test(trimmed)
    const score = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length
    if (trimmed.length >= 12 && score >= 3) return 'strong'
    if (trimmed.length >= 8 && score >= 2) return 'medium'
    return 'weak'
  }

  const handlePasswordChange = (e) => {
    const val = e.target.value
    setPassword(val)
    const trimmed = val.trim()
    if (val && trimmed.length === 0) {
      setPasswordError('Password cannot be only whitespace')
    } else if (trimmed && trimmed.length < MIN_PASSWORD_LENGTH) {
      setPasswordError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
    } else {
      setPasswordError('')
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess(false)

    if (!image) {
      setError('Please select an image')
      return
    }

    if (mode === 'file' && !file) {
      setError('Please select a file to hide')
      return
    }

    if (mode === 'text' && !text.trim()) {
      setError('Please enter some text to hide')
      return
    }

    const trimmedPassword = password.trim()
    if (v6Mode === 'encrypted') {
      if (!trimmedPassword) {
        setError('Password is required for Encrypted mode')
        return
      }
      if (trimmedPassword.length < MIN_PASSWORD_LENGTH) {
        setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters long`)
        return
      }
    }

    setLoading(true)

    try {
      const formData = new FormData()
      formData.append('image', image)

      if (mode === 'file') {
        formData.append('file', file)
      } else {
        formData.append('text', text.trim())
      }

      formData.append('mode', v6Mode)
      if (v6Mode === 'encrypted' && trimmedPassword) {
        formData.append('password', trimmedPassword)
      }

      const response = await axios.post(`${API_URL}/api/hide-v6`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      })

      setDownloadId(response.data.download_id)
      setSuccess(true)
      setImage(null)
      setFile(null)
      setText('')
      setPassword('')
      setPasswordError('')
      setShowPassword(false)
    } catch (err) {
      setError(await getApiErrorMessage(err, 'An error occurred while hiding the file'))
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = async () => {
    if (!downloadId || downloading) return
    setDownloading(true)
    setError('')
    try {
      const response = await axios.get(`${API_URL}/api/download/${downloadId}`, {
        responseType: 'blob'
      })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', 'invisiovault_image.png')
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (err) {
      setError(await getApiErrorMessage(err, 'Failed to download the generated image'))
    } finally {
      setDownloading(false)
    }
  }

  const handleReset = () => {
    setSuccess(false)
    setDownloadId('')
    setError('')
    setPasswordError('')
    setShowPassword(false)
  }

  const processingStages = useMemo(() => [
    'Analyzing carrier RGB channels...',
    v6Mode === 'encrypted'
      ? 'Applying password-protected encryption with authenticated integrity...'
      : 'Computing CRC-32 integrity checksum...',
    'Applying Reed-Solomon RS(255, 223) dynamic interleaving...',
    'Executing 10-round Feistel permutation & Matrix (3,2) coset embedding...',
    'Finalizing lossless V6 stego PNG...'
  ], [v6Mode])

  return (
    <div className="hide-file">
      <h2>Hide a File in an Image</h2>
      <p className="description">
        Upload an image and a file. The file will be securely hidden within the image using steganography.
      </p>

      {/* Visual Step Progression */}
      <StepProgress steps={STEPS} currentStep={getCurrentStep()} isComplete={success} />

      {!success ? (
        <form onSubmit={handleSubmit}>
          {/* Steganography Engine Identification */}
          <div className="engine-identity-bar">
            <div className="engine-identity-info">
              <span className="engine-identity-badge v6">
                <Cpu size={13} aria-hidden="true" />
                <span>V6 · ADVANCED</span>
              </span>
              <div className="engine-identity-text">
                <span className="engine-identity-title">STEGANOGRAPHY ENGINE</span>
                <span className="engine-identity-specs">
                  Matrix embedding · Feistel permutation · Reed-Solomon error correction
                </span>
              </div>
            </div>
          </div>

          {/* Payload Type Navigation (Tabs) */}
          <div className="payload-type-nav" role="tablist" aria-label="Payload type">
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'file'}
              className={`payload-tab-btn ${mode === 'file' ? 'active' : ''}`}
              onClick={() => handleModeChange('file')}
            >
              <FileText size={16} aria-hidden="true" />
              <span>Hide File</span>
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={mode === 'text'}
              className={`payload-tab-btn ${mode === 'text' ? 'active' : ''}`}
              onClick={() => handleModeChange('text')}
            >
              <Type size={16} aria-hidden="true" />
              <span>Hide Text</span>
            </button>
          </div>

          {/* Carrier Image Dropzone */}
          <FileDropzone
            id="carrier-image-input"
            label="Carrier Image (PNG, JPG, JPEG, BMP)"
            accept="image/png,image/jpeg,image/bmp"
            file={image}
            onFileSelect={(f) => { setImage(f); setError(''); }}
            onClear={() => setImage(null)}
            helperText="Drag & drop or browse from device (PNG, JPG, or BMP)"
            required
            disabled={loading}
          />

          {mode === 'file' ? (
            /* Secret File Dropzone */
            <FileDropzone
              id="secret-file-input"
              label="Secret File to Hide"
              file={file}
              onFileSelect={(f) => { setFile(f); setError(''); }}
              onClear={() => setFile(null)}
              helperText="Any file type (documents, archives, keys, media)"
              disabled={loading}
            />
          ) : (
            <div className="form-group">
              <label htmlFor="text-input">Enter Text to Hide</label>
              <textarea
                id="text-input"
                placeholder="Type your secret message here..."
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows="5"
                disabled={loading}
                aria-describedby={text ? 'text-char-count' : undefined}
              />
              {text && <p id="text-char-count" className="char-count" aria-live="polite">Characters: {text.length}</p>}
            </div>
          )}

          {/* Encryption Mode Selection (Balanced Cards) */}
          <div className="v6-mode-section">
            <span className="v6-mode-section-label">ENCRYPTION MODE</span>
            <div className="v6-mode-cards" role="radiogroup" aria-label="Encryption Mode">
              <button
                type="button"
                role="radio"
                aria-checked={v6Mode === 'encrypted'}
                className={`mode-card ${v6Mode === 'encrypted' ? 'selected' : ''}`}
                onClick={() => { setV6Mode('encrypted'); setError(''); }}
              >
                <div className="mode-card-header">
                  <div className="mode-card-icon-wrap">
                    <Lock size={18} aria-hidden="true" />
                  </div>
                  <div className="mode-card-title-wrap">
                    <span className="mode-card-title">Encrypted Mode</span>
                    <span className="mode-card-sub required">Password Required</span>
                  </div>
                </div>
                <p className="mode-card-description">
                  Password-protected encryption with authenticated integrity.
                </p>
              </button>

              <button
                type="button"
                role="radio"
                aria-checked={v6Mode === 'plain'}
                className={`mode-card ${v6Mode === 'plain' ? 'selected' : ''}`}
                onClick={() => {
                  setV6Mode('plain');
                  setPassword('');
                  setPasswordError('');
                  setError('');
                }}
              >
                <div className="mode-card-header">
                  <div className="mode-card-icon-wrap">
                    <ShieldCheck size={18} aria-hidden="true" />
                  </div>
                  <div className="mode-card-title-wrap">
                    <span className="mode-card-title">Plain Mode</span>
                    <span className="mode-card-sub plain">No Password Required</span>
                  </div>
                </div>
                <p className="mode-card-description">
                  Integrity-verified embedding without password protection.
                </p>
              </button>
            </div>
          </div>

          {/* Password Input: Only displayed when Encrypted Mode is active */}
          {v6Mode === 'encrypted' && (
            <div className="form-group">
              <label htmlFor="password-input" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                <span>Password (Required)</span>
                <Lock size={14} style={{ opacity: 0.7 }} aria-hidden="true" />
              </label>
              <div className="password-input-wrapper">
                <input
                  id="password-input"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter password (min. 8 characters)"
                  value={password}
                  onChange={handlePasswordChange}
                  aria-describedby={passwordError ? 'hide-password-error' : undefined}
                  disabled={loading}
                />
                {password && (
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    aria-pressed={showPassword}
                    disabled={loading}
                  >
                    {showPassword ? (
                      <EyeOff size={18} aria-hidden="true" />
                    ) : (
                      <Eye size={18} aria-hidden="true" />
                    )}
                  </button>
                )}
              </div>
              {passwordError && (
                <p id="hide-password-error" className="password-error-msg" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }} role="alert">
                  <AlertTriangle size={14} style={{ flexShrink: 0 }} aria-hidden="true" />
                  <span>{passwordError}</span>
                </p>
              )}
              {password && !passwordError && (
                <div className="password-strength" role="status" aria-live="polite">
                  <div className={`strength-bar strength-${getPasswordStrength(password)}`}>
                    <span></span><span></span><span></span>
                  </div>
                  <p className="file-name">
                    {getPasswordStrength(password) === 'strong' && (
                      <>
                        <ShieldCheck size={14} aria-hidden="true" />
                        <span>Strong password</span>
                      </>
                    )}
                    {getPasswordStrength(password) === 'medium' && (
                      <>
                        <ShieldAlert size={14} aria-hidden="true" />
                        <span>Medium strength — consider adding symbols or numbers</span>
                      </>
                    )}
                    {getPasswordStrength(password) === 'weak' && (
                      <>
                        <ShieldX size={14} aria-hidden="true" />
                        <span>Weak password</span>
                      </>
                    )}
                  </p>
                </div>
              )}
              {password && !passwordError && (
                <p className="file-name">
                  <Lock size={14} aria-hidden="true" />
                  <span>File will be password-protected</span>
                </p>
              )}
            </div>
          )}

          {/* Capacity Indicator */}
          {image && hasActivePayload && (
            <CapacityIndicator
              carrierFile={image}
              hiddenFile={mode === 'file' ? file : null}
              hiddenText={mode === 'text' ? text.trim() : ''}
              mode="stego"
              password={v6Mode === 'plain' ? '' : password.trim()}
              engine="v6"
            />
          )}

          {error && <div className="error-message" role="alert">{error}</div>}

          {/* Staged Micro-Processing Indicator */}
          <ProcessingIndicator
            isActive={loading}
            stages={processingStages}
          />

          <button
            type="submit"
            disabled={loading}
            className="submit-button"
            aria-busy={loading}
          >
            {loading ? 'Hiding File...' : 'Hide File'}
          </button>
        </form>
      ) : (
        <div className="success-card">
          <div className="success-icon">
            <CheckCircle2 size={48} strokeWidth={1.75} aria-hidden="true" />
          </div>
          <h3>File Hidden Successfully!</h3>
          {error && (
            <div className="error-message" role="alert" style={{ marginBottom: '1rem' }}>
              {error}
            </div>
          )}
          <button type="button" onClick={handleDownload} disabled={downloading} className="download-button">
            <Download size={16} aria-hidden="true" />
            <span>{downloading ? 'Downloading...' : 'Download Image'}</span>
          </button>
          <button
            type="button"
            onClick={handleReset}
            className="new-button"
          >
            Hide Another File
          </button>
        </div>
      )}
    </div>
  )
}

export default HideFile
