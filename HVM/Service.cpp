#include "Service.h"

EXTERN_C_BEGIN

#define DEVICE_NAME L"\\Device\\HVM_DEVICE"
#define SYMBOL_LINK_NAME L"\\??\\HVM_SYMBOL_LINK"

//�����豸��ǲ����
NTSTATUS IODeviceControlFunction(PDEVICE_OBJECT pDeviceObj, PIRP pIRP)
{
	//��ȡIRP����
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIRP);
	//��ȡ������
	ULONG uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//��ȡ��������ַ(���������Ļ���������һ��)
	PVOID pBuff = pIRP->AssociatedIrp.SystemBuffer;
	//Ring 3 �������ݵĳ���
	ULONG inLenth = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//Ring 0 �������ݵĳ���
	ULONG outLenth = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	switch (uIoControlCode)
	{
	//case OPER1:
	//	DbgPrint("OPER1\r\n");
	//	break;
	//case OPER2:
	//	DbgPrint("OPER2\r\n");
	//	break;
	//case �ر�ͨѶ:
	//	pDeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;
	default:
		break;
	}

	//���÷���״̬
	pIRP->IoStatus.Status = STATUS_SUCCESS;//GetLastError()�õ��ľ������ֵ
	pIRP->IoStatus.Information = 0;//���ظ�3�������ֽڵ�����
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS CreateDeviceFunction(PDEVICE_OBJECT pDeviceObj, PIRP pIRP)
{
	DbgPrint("CreateDeviceFunction\r\n");

	//���÷���״̬
	pIRP->IoStatus.Status = STATUS_SUCCESS;//GetLastError()�õ��ľ������ֵ
	pIRP->IoStatus.Information = 0;//���ظ�3�������ֽڵ�����

	//pDeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS SerEstablishComunication(PDRIVER_OBJECT pDriver)
{
	NTSTATUS status = 0;
	PDEVICE_OBJECT pDevice;

	//�����豸����
	UNICODE_STRING deviceName;
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);

	//�����豸
	status = IoCreateDevice(
		pDriver,//�豸��������������
		0,
		&deviceName,//�豸��
		FILE_DEVICE_UNKNOWN,//�豸����
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDevice//out�豸ָ��
	);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("�����豸����ʧ��!\r\n");
		return status;
	}

	//ָ���豸ͨѶ��ʽ
	pDevice->Flags = DO_BUFFERED_IO;//��������ȡ(��3�������ݸ��Ƶ�0���ٶ�ȡ)
	//pDevice->Flags = DO_DIRECT_IO;//ֱ�Ӷ�ȡ(����������ҳӳ�䵽0��,����ס����ҳ)



	//����������������
	UNICODE_STRING symbolLinkName;
	RtlInitUnicodeString(&symbolLinkName, SYMBOL_LINK_NAME);

	//������������
	status = IoCreateSymbolicLink(
		&symbolLinkName,
		&deviceName
	);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("������������ʧ��!\r\n");
		return status;
	}
	//������ǲ����
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IODeviceControlFunction;
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDeviceFunction;
}

EXTERN_C_END