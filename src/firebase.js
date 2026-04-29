import { initializeApp } from "firebase/app";
import { getDatabase, ref, push, query, orderByChild, limitToLast, get } from "firebase/database";

const firebaseConfig = {
  apiKey: "AIzaSyAdM1wr9LsJHdO4A-xwQoWeO3_m4I9qeBQ",
  authDomain: "xrypt-security.firebaseapp.com",
  databaseURL: "https://xrypt-security-default-rtdb.firebaseio.com",
  projectId: "xrypt-security",
  storageBucket: "xrypt-security.firebasestorage.app",
  messagingSenderId: "584283400291",
  appId: "1:584283400291:web:01d382fd85658d79af3056"
};

const app = initializeApp(firebaseConfig);
export const db = getDatabase(app);
export { ref, push, query, orderByChild, limitToLast, get };