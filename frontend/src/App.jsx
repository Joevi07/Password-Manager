import { useState } from 'react'

import SecureVault from './components/SecureVault'

function App() {
  const [count, setCount] = useState(0)

  return (
   <>
   <SecureVault/>
   </>
  )
}

export default App
