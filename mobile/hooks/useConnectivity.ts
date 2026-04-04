import NetInfo from "@react-native-community/netinfo";
import { useEffect, useState } from "react";

export function useConnectivity() {
  const [isOnline, setIsOnline] = useState(true);

  useEffect(() => {
    const subscription = NetInfo.addEventListener((state) => {
      setIsOnline(Boolean(state.isConnected && state.isInternetReachable !== false));
    });
    return () => subscription();
  }, []);

  return { isOnline };
}

