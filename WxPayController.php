<?php
/**
 * 支付
 * Author: CK
 * Date: 2017/12/26
 */

namespace Modules\Backend\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Modules\Backend\Models\User;


class PayController extends Controller
{

    public function __construct()
    {
        $config = array(
            'appid' => 'wx5e37eded815240ff',//小程序appid
            'pay_mchid' => '1410153202',//商户号
            'pay_apikey' => '57D09762574d0e37d7bd5Be1f2fe8046',//可在微信商户后台生成支付秘钥
        );
        $this->config = $config;
    }

    #提现
    public function getRefundConfig(Request $request)
    {
        $params = $request->all();
        if (!isset($params['openid'])) {
            return ['code' => 90002, 'msg' => 'openid不存在'];
        }
        if (!isset($params['amount'])) {
            return ['code' => 90002, 'msg' => '提现金额不存在'];
        }
        #判断是否存在此用户 账户余额
        $exitUsr = User::where('openid', $params['openid'])->first();
        if (!$exitUsr) {
            return ['code' => 90002, 'msg' => '用户不存在'];
        }
        if ($exitUsr['user_account'] > $params['amount']) {
            $config = $this->config;
            $order_sn = 'HB' . date('YmdHis', time());
            $data = [
                'mch_appid' => $config['appid'],
                'mchid' => $config['pay_mchid'],
                'nonce_str' => $this->getRangChar(),
                'partner_trade_no' => $order_sn,
                'openid' => $params['openid'],
                'check_name' => 'NO_CHECK',
                're_user_name' => 'hebeit',
                'amount' => $params['amount'] * 100,
                'desc' => '提现费用',
                'spbill_create_ip' => $request->getClientIp(),
            ];
            $data['sign'] = self::makeSign($data);
            #数组转xml
            $xmldata = self::array2xml($data);
            $url = 'https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers';
            $res = self::curl($url, $xmldata);
            if (!$res) {
                return ['code' => 90002, 'msg' => '系统错误,请稍后再试'];
            }
            #xml转数组
            $content = self::xml2array($res);
            #错误提示
            if ($content['result_code'] == 'FAIL') {
                return $this->refunErr($content['err_code']);
            }
            $user['openid'] = $params['openid'];
            $user['user_account'] = $exitUsr['user_account'] - $params['amount'];
            User::userEdit($user);
            return $content;
        } else {
            return ['code' => 90002, 'msg' => '您的余额不足'];
        }
    }

    #体现错误码
    public function refunErr($params)
    {
        $err = ['NO_AUTH', 'AMOUNT_LIMIT', 'PARAM_ERROR', 'OPENID_ERROR', 'SEND_FAILED', 'NOTENOUGH', 'SYSTEMERROR', 'NAME_MISMATCH'
            , 'SIGN_ERROR', 'XML_ERROR', 'FATAL_ERROR', 'FREQ_LIMIT', 'MONEY_LIMIT', 'CA_ERROR', 'V2_ACCOUNT_SIMPLE_BAN', 'PARAM_IS_NOT_UTF8', 'AMOUNT_LIMIT'];
        if (in_array($params, $err)) {
            return ['code' => 90002, 'msg' => '请求超时,请稍后再试'];
        }
    }


    public function curl($url, $xmldata, $second = 30, $aHeader = array())
    {
        $ch = curl_init();
        //超时时间
        curl_setopt($ch, CURLOPT_TIMEOUT, $second);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        if (count($aHeader) >= 1) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $aHeader);
        }
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xmldata);

        curl_setopt($ch, CURLOPT_SSLCERT, getcwd() . '/cert/apiclient_cert.pem'); //这个是证书的位置
        curl_setopt($ch, CURLOPT_SSLKEY, getcwd() . '/cert/apiclient_key.pem'); //这个也是证书的位置


        $data = curl_exec($ch);
        if ($data) {
            curl_close($ch);
            return $data;
        } else {
            $error = curl_errno($ch);
            echo "call faild, errorCode:$error\n";
            curl_close($ch);
            return false;
        }
    }


    #支付配置
    public function getPayConfig(Request $request)
    {
        $params = $request->all();
        if (!isset($params['order_sn'])) {
            return ['code' => 90002, 'msg' => '订单号不存在'];
        }
        if (!isset($params['openid'])) {
            return ['code' => 90002, 'msg' => 'openid不存在'];
        }
        if (!isset($params['goods_money'])) {
            return ['code' => 90002, 'msg' => '商品金额不存在'];
        }
        if (!isset($params['goods_name'])) {
            return ['code' => 90002, 'msg' => '商品名称不存在'];
        }
        $config = $this->config;
        $data = [
            'appid' => $config['appid'],
            'mch_id' => $config['pay_mchid'],
            'nonce_str' => $this->getRangChar(),
            'body' => $params['goods_name'],
            'out_trade_no' => $params['order_sn'],
            'total_fee' => $params['goods_money'] * 100,
            'spbill_create_ip' => $request->getClientIp(),
            'notify_url' => 'http://' . $_SERVER['HTTP_HOST'] . '/backend/pay-notify',
            'trade_type' => 'JSAPI',
            'openid' => $params['openid'],
        ];
        #签名
        $data['sign'] = self::makeSign($data);
        #数组转xml
        $xmldata = self::array2xml($data);
        $url = 'https://api.mch.weixin.qq.com/pay/unifiedorder';
        $res = self::curl_post_ssl($url, $xmldata);
        if (!$res) {
            return ['code' => 90002, 'msg' => '支付失败'];
        }
        #xml转数组
        $content = self::xml2array($res);
        $result = $this->pay($content);
        return ['code' => 1, 'data' => $result];
    }

//post
    protected function curl_post_ssl($url, $xmldata, $second = 30, $aHeader = array())
    {
        $ch = curl_init();
        //超时时间
        curl_setopt($ch, CURLOPT_TIMEOUT, $second);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        if (count($aHeader) >= 1) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, $aHeader);
        }
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xmldata);


        $data = curl_exec($ch);
        if ($data) {
            curl_close($ch);
            return $data;
        } else {
            $error = curl_errno($ch);
            echo "call faild, errorCode:$error\n";
            curl_close($ch);
            return false;
        }
    }


    public function pay($content)
    {
        $config = $this->config;
        $data = array(
            'appId' => $content['appid'],
            'timeStamp' => time(),
            'nonceStr' => $this->getRangChar(),
            'package' => 'prepay_id=' . $content['prepay_id'],
            'signType' => 'MD5'
        );
        $data['paySign'] = self::makeSign($data);
        return $data;
    }


    #随机生成16位字符串
    public function getRangChar($length = 32)
    {
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    protected function makeSign($data)
    {
        //获取微信支付秘钥
        $key = $this->config['pay_apikey'];
        // 去空
        $data = array_filter($data);
        //签名步骤一：按字典序排序参数
        ksort($data);
        $string_a = http_build_query($data);
        $string_a = urldecode($string_a);
        //签名步骤二：在string后加入KEY
        //$config=$this->config;
        $string_sign_temp = $string_a . "&key=" . $key;
        //签名步骤三：MD5加密
        $sign = md5($string_sign_temp);
        // 签名步骤四：所有字符转为大写
        $result = strtoupper($sign);
        return $result;
    }


    //回调
    public function notify()
    {
        return 123;
    }

    # 将xml转为array
    protected function xml2array($xml)
    {
        //禁止引用外部xml实体
        (true);
        $result = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        return $result;
    }


    # 将一个数组转换为 XML 结构的字符串
    protected function array2xml($arr, $level = 1)
    {
        $s = $level == 1 ? "<xml>" : '';
        foreach ($arr as $tagname => $value) {
            if (is_numeric($tagname)) {
                $tagname = $value['TagName'];
                unset($value['TagName']);
            }
            if (!is_array($value)) {
                $s .= "<{$tagname}>" . (!is_numeric($value) ? '<![CDATA[' : '') . $value . (!is_numeric($value) ? ']]>' : '') . "</{$tagname}>";
            } else {
                $s .= "<{$tagname}>" . $this->array2xml($value, $level + 1) . "</{$tagname}>";
            }
        }
        $s = preg_replace("/([\x01-\x08\x0b-\x0c\x0e-\x1f])+/", ' ', $s);
        return $level == 1 ? $s . "</xml>" : $s;
    }


}
