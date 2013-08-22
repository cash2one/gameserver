/**
 * \brief ʵ�����������
 *
 * 
 */
#include <zebra/srvEngine.h>

#include <iostream>
#include <string>
//#include <ext/numeric>

zMNetService *zMNetService::instance = NULL;

/**
 * \brief ��ʼ������������
 *
 * ʵ��<code>x_service::init</code>���麯��
 *
 * \return �Ƿ�ɹ�
 */
bool zMNetService::init()
{
  Xlogger->debug("zMNetService::init");

  if (!x_service::init())
    return false;

  //��ʼ��������
  tcpServer = new zMTCPServer(serviceName);
  if (NULL == tcpServer)
    return false;

  return true;
}

/**
 * \brief ��������������ص�����
 *
 * ʵ���麯��<code>x_service::serviceCallback</code>����Ҫ���ڼ�������˿ڣ��������false���������򣬷���true����ִ�з���
 *
 * \return �ص��Ƿ�ɹ�
 */
bool zMNetService::serviceCallback()
{
  Xlogger->debug("zMNetService::serviceCallback");
  // [ranqd] ÿ�����һ�������������
  zRTime currentTime;
  currentTime.now();
  if( _one_sec_( currentTime ) )
  {
	  zIocp::getInstance().UpdateNetLog();
  }

  zMTCPServer::Sock2Port res;
  if (tcpServer->accept(res) > 0) 
  {
    for(zMTCPServer::Sock2Port_const_iterator it = res.begin(); it != res.end(); it++)
    {
      if (it->first >= 0)
      {
        //�������ӳɹ�����������
        newTCPTask(it->first,it->second);
      }
    }
  }

  return true;
}

/**
 * \brief �����������������
 *
 * ʵ�ִ��麯��<code>x_service::final</code>��������Դ
 *
 */
void zMNetService::final()
{
  Xlogger->debug("zMNetService::final");
  SAFE_DELETE(tcpServer);
}

