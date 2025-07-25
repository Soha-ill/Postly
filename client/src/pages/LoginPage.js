import {useContext, useState} from "react";
import {Navigate} from "react-router-dom";
import {UserContext} from "../UserContext";

export default function LoginPage() {
  const [identifier, setIdentifier] = useState('');
const [password, setPassword] = useState('');
const [redirect, setRedirect] = useState(false);
const { setUserInfo } = useContext(UserContext);

async function login(ev) {
  ev.preventDefault();
  const response = await fetch('${process.env.REACT_APP_API_URL}/login', {
    method: 'POST',
    body: JSON.stringify({ identifier, password }),
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
  });

  if (response.ok) {
    response.json().then(userInfo => {
      setUserInfo(userInfo);
      setRedirect(true);
    });
  } else {
    alert('wrong credentials');
  }
}

  if (redirect) {
    return <Navigate to={'/'} />
  }
  return (
    <form className="login" onSubmit={login}>
      <h1>Login</h1>
      <input type="text"
             placeholder="Username or Email"
             value={identifier}
             onChange={ev => setIdentifier(ev.target.value)}/>
      <input type="password"
             placeholder="password"
             value={password}
             onChange={ev => setPassword(ev.target.value)}/>
      <button>Login</button>
    </form>
  );
}