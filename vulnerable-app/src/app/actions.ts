// ⚠️ WARNING: This file contains a Server Action that demonstrates
// the pattern vulnerable to CVE-2025-66478 in unpatched versions.
// This is for EDUCATIONAL PURPOSES ONLY.

'use server'

// This server action receives data from the client
// In vulnerable versions, the deserialization of this data can be exploited
export async function submitOrder(formData: FormData) {
  const customerName = formData.get('customerName') as string
  const productId = formData.get('productId') as string
  const quantity = parseInt(formData.get('quantity') as string, 10)

  // Simulate order processing
  console.log('Processing order:', { customerName, productId, quantity })

  // In a real app, this would interact with a database
  return {
    success: true,
    orderId: `ORD-${Date.now()}`,
    message: `Order received for ${customerName}`
  }
}

// Another server action example
export async function getUserData(userId: string) {
  // This function receives user input from the client
  // The vulnerability exists in how React deserializes the arguments
  // sent to this function, not in the function implementation itself
  
  console.log('Fetching user data for:', userId)
  
  // Simulated user data
  return {
    id: userId,
    name: 'Demo User',
    email: 'demo@example.com'
  }
}
