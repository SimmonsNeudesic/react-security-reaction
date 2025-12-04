'use client'

import { submitOrder } from './actions'
import { useState } from 'react'

export default function Home() {
  const [result, setResult] = useState<string>('')

  async function handleSubmit(formData: FormData) {
    const response = await submitOrder(formData)
    setResult(JSON.stringify(response, null, 2))
  }

  return (
    <main style={{ padding: '2rem', fontFamily: 'system-ui', backgroundColor: '#FFF9E5' }}>
      <div style={{ 
        backgroundColor: '#ffcccc', 
        border: '3px solid #cc0000',
        padding: '1rem',
        marginBottom: '2rem',
        borderRadius: '8px'
      }}>
        <h1 style={{ color: '#cc0000', margin: 0 }}>
          ⚠️ SECURITY WARNING
        </h1>
        <p style={{ margin: '0.5rem 0' }}>
          This application is <strong>INTENTIONALLY VULNERABLE</strong> to CVE-2025-66478.
        </p>
        <p style={{ margin: '0.5rem 0' }}>
          <strong>DO NOT</strong> deploy this to any environment. For testing purposes only.
        </p>
      </div>

      <h2>Vulnerable Demo Application</h2>
      <p>
        This application uses <code>next@15.0.0</code> and <code>react@19.0.0</code>, 
        which are affected by CVE-2025-66478 / CVE-2025-55182.
      </p>

      <div style={{ 
        backgroundColor: '#f0f0f0', 
        padding: '1rem', 
        borderRadius: '8px',
        marginTop: '1rem'
      }}>
        <h3>Server Action Demo</h3>
        <p style={{ fontSize: '0.9rem', color: '#666' }}>
          This form uses a Server Action. In vulnerable versions, the data sent to
          the server can be exploited through malicious deserialization.
        </p>
        
        <form action={handleSubmit} style={{ marginTop: '1rem' }}>
          <div style={{ marginBottom: '1rem' }}>
            <label htmlFor="customerName">Customer Name:</label><br />
            <input 
              type="text" 
              id="customerName"
              name="customerName" 
              defaultValue="Test Customer"
              style={{ padding: '0.5rem', width: '300px' }}
            />
          </div>
          
          <div style={{ marginBottom: '1rem' }}>
            <label htmlFor="productId">Product ID:</label><br />
            <input 
              type="text" 
              id="productId"
              name="productId" 
              defaultValue="PROD-001"
              style={{ padding: '0.5rem', width: '300px' }}
            />
          </div>
          
          <div style={{ marginBottom: '1rem' }}>
            <label htmlFor="quantity">Quantity:</label><br />
            <input 
              type="number" 
              id="quantity"
              name="quantity" 
              defaultValue={1}
              style={{ padding: '0.5rem', width: '100px' }}
            />
          </div>
          
          <button 
            type="submit"
            style={{ 
              padding: '0.5rem 1rem', 
              backgroundColor: '#0070f3', 
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Submit Order (Server Action)
          </button>
        </form>

        {result && (
          <div style={{ marginTop: '1rem' }}>
            <h4>Response:</h4>
            <pre style={{ 
              backgroundColor: '#e0e0e0', 
              padding: '1rem',
              borderRadius: '4px',
              overflow: 'auto'
            }}>
              {result}
            </pre>
          </div>
        )}
      </div>

      <div style={{ marginTop: '2rem', borderTop: '1px solid #ccc', paddingTop: '1rem' }}>
        <h3>About This Page</h3>
        <ul>
          <li><strong>CVE:</strong> CVE-2025-66478 (Next.js) / CVE-2025-55182 (React)</li>
          <li><strong>Severity:</strong> CVSS 10.0 (Critical)</li>
          <li><strong>Type:</strong> CWE-502 - Deserialization of Untrusted Data</li>
          <li><strong>Impact:</strong> Unauthenticated Remote Code Execution</li>
        </ul>
        
        <h4>To Fix This Application:</h4>
        <pre style={{ 
          backgroundColor: '#e8f5e9', 
          padding: '1rem',
          borderRadius: '4px',
          border: '1px solid #4caf50'
        }}>
{`npm install next@15.0.5
# or for other versions:
npm install next@15.1.9  # for 15.1.x
npm install next@15.2.6  # for 15.2.x
npm install next@15.3.6  # for 15.3.x
npm install next@15.4.8  # for 15.4.x
npm install next@15.5.7  # for 15.5.x
npm install next@16.0.7  # for 16.0.x`}
        </pre>
      </div>
    </main>
  )
}
