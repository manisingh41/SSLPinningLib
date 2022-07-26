//
//  SSLPinning.swift
//  SSLPinningLib
//
//  Created by Nagmani Singh on 26/07/22.
//

import Foundation

public class SSLPinning: NSObject{
    public var certificateName: String?
    
}
extension SSLPinning: URLSessionDelegate{
    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            guard let serverTrust = challenge.protectionSpace.serverTrust else {
                completionHandler(.cancelAuthenticationChallenge, nil);
                return
            }
            
            let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
            
            // SSL Policies for domain name check
            let policy = NSMutableArray()
            policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
            
            //evaluate server certifiacte
            let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
            
            //Local and Remote certificate Data
            let remoteCertificateData:NSData =  SecCertificateCopyData(certificate!)
            
        let pathToCertificate = Bundle.main.path(forResource: self.certificateName, ofType: "cer")
            let localCertificateData:NSData = NSData(contentsOfFile: pathToCertificate!)!
            //Compare certificates
            if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
                let credential:URLCredential =  URLCredential(trust:serverTrust)
                print("Certificate pinning is successfully completed")
                completionHandler(.useCredential,nil)
            }
            else {
                DispatchQueue.main.async {
                    //self.showAlert(text: "SSL Pinning", message: "Pinning failed")
                    print("Certificate pinning is failed")
                }
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        }
}
