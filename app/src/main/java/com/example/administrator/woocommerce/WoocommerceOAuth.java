package com.example.administrator.woocommerce;

import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import org.json.JSONObject;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Administrator on 2016/6/2 0002.
 */
 class WoocommerceOAuth extends AsyncTask<Void,Void,Void> {

    List<Pair<String, String>> parameters;
    private static final String CONSUMERKEY = "ck_71502d90c592643838bc2ec4f1ae26182680a220";
    private static final String CONSUMERSECRET = "cs_26858a251f582e9cbc1ec1197d7751407e4df8ac";
    private static final String METHOD = "HMAC-SHA1";
    private static final String URL = "http://intense-harbor-66172.herokuapp.com/wc-api/v3/orders";
    private static final String PARAMNAME_KEY = "oauth_consumer_key";
    private static final String PARAMNAME_SECRET = "oauth_consumer_secret";
    private static final String PARAMNAME_NONCE = "oauth_nonce";
    private static final String PARAMNAME_TIMESTAMP = "oauth_timestamp";
    private static final String PARAMNAME_SIGNATURE = "oauth_signature";
    private static final String PARAMNAME_SIGNATURE_METHOD = "oauth_signature_method";
    JSONObject response;
    @Override
    protected Void doInBackground(Void... params) {
        String timestamp = System.currentTimeMillis() / 1000 + "";
        String nonce =  (Math.random() * 100000000) + "";
        String encoded_base_url ="";
        parameters = new ArrayList<>();
        parameters.add(new Pair<>("oauth_consumer_key",CONSUMERKEY));
        parameters.add(new Pair<>("oauth_consumer_secret",CONSUMERSECRET));
        parameters.add(new Pair<>("oauth_timestamp",timestamp));
        parameters.add(new Pair<>("oauth_nonce",nonce));
        parameters.add(new Pair<>("oauth_signature_method",METHOD));
        try {
            encoded_base_url = "GET&" + URLEncoder.encode(URL, "UTF-8") + "&";
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Log.d("encoded url", encoded_base_url);
        StringBuilder builder = new StringBuilder();
        builder.append(PARAMNAME_KEY + "=" + CONSUMERKEY + "&");
        builder.append(PARAMNAME_SECRET + "=" + CONSUMERSECRET + "&");
        builder.append(PARAMNAME_NONCE + "=" + nonce + "&");
        builder.append(PARAMNAME_SIGNATURE_METHOD + "=" + METHOD + "&");
        builder.append(PARAMNAME_TIMESTAMP + "=" + timestamp);
        String str = builder.toString();
        try {
            str = URLEncoder.encode(str,"UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Log.d("prepared string", str);
        String signature = encoded_base_url + str;
        String encoded = "";
        try {
            Mac mac = Mac.getInstance(METHOD);
            byte[] key = CONSUMERSECRET.getBytes("utf-8");
            SecretKey secretKey = new SecretKeySpec(key, METHOD);
            mac.init(secretKey);
            byte[] signaturebytes = mac.doFinal(signature
                    .getBytes("utf-8"));
            encoded = Base64.encodeToString(signaturebytes,
                    Base64.DEFAULT).trim();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Log.d("signature", encoded);
        parameters.add(new Pair<>(PARAMNAME_SIGNATURE,
                encoded));


//        response = jparser.makeHttpRequest(
//                URL,
//                "GET", parameters);


        return null;
    }
}
