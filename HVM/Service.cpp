#include "Service.h"

EXTERN_C_BEGIN

#define DEVICE_NAME L"\\Device\\HVM_DEVICE"
#define SYMBOL_LINK_NAME L"\\??\\HVM_SYMBOL_LINK"

//创建设备派遣函数
NTSTATUS IODeviceControlFunction(PDEVICE_OBJECT pDeviceObj, PIRP pIRP)
{
	//获取IRP数据
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIRP);
	//获取控制码
	ULONG uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//获取缓冲区地址(输入和输出的缓冲区都是一个)
	PVOID pBuff = pIRP->AssociatedIrp.SystemBuffer;
	//Ring 3 发送数据的长度
	ULONG inLenth = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//Ring 0 发送数据的长度
	ULONG outLenth = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	switch (uIoControlCode)
	{
	//case OPER1:
	//	DbgPrint("OPER1\r\n");
	//	break;
	//case OPER2:
	//	DbgPrint("OPER2\r\n");
	//	break;
	//case 关闭通讯:
	//	pDeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;
	default:
		break;
	}

	//设置返回状态
	pIRP->IoStatus.Status = STATUS_SUCCESS;//GetLastError()得到的就是这个值
	pIRP->IoStatus.Information = 0;//返回给3环多少字节的数据
	IoCompleteRequest(pIRP, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS CreateDeviceFunction(PDEVICE_OBJECT pDeviceObj, PIRP pIRP)
{
	DbgPrint("CreateDeviceFunction\r\n");

	//设置返回状态
	pIRP->IoStatus.Status = STATUS_SUCCESS;//GetLastError()得到的就是这个值
	pIRP->IoStatus.Information = 0;//返回给3环多少字节的数据

	//pDeviceObj->Flags &= ~DO_DEVICE_INITIALIZING;

	IoCompleteRequest(pIRP, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS SerEstablishComunication(PDRIVER_OBJECT pDriver)
{
	NTSTATUS status = 0;
	PDEVICE_OBJECT pDevice;

	//创建设备名称
	UNICODE_STRING deviceName;
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);

	//创建设备
	status = IoCreateDevice(
		pDriver,//设备所属的驱动对象
		0,
		&deviceName,//设备名
		FILE_DEVICE_UNKNOWN,//设备类型
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDevice//out设备指针
	);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("创建设备对象失败!\r\n");
		return status;
	}

	//指定设备通讯方式
	pDevice->Flags = DO_BUFFERED_IO;//缓冲区读取(将3环的数据复制到0环再读取)
	//pDevice->Flags = DO_DIRECT_IO;//直接读取(将数据物理页映射到0环,会锁住物理页)



	//创建符号链接名称
	UNICODE_STRING symbolLinkName;
	RtlInitUnicodeString(&symbolLinkName, SYMBOL_LINK_NAME);

	//创建符号链接
	status = IoCreateSymbolicLink(
		&symbolLinkName,
		&deviceName
	);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("创建符号链接失败!\r\n");
		return status;
	}
	//设置派遣函数
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IODeviceControlFunction;
	pDriver->MajorFunction[IRP_MJ_CREATE] = CreateDeviceFunction;
}

EXTERN_C_END