/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"
#include "structures.h"

#pragma NDIS_INIT_FUNCTION(FilterRegisterDevice)

VOID AddIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN PRULE_IPV4 Rule);
VOID DelIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN ULONG Id);
VOID ActivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension);
VOID DeactivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension);
VOID LoadRule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension);

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
FilterRegisterDevice(OUT PFILTER_DEVICE_EXTENSION *Extension)
{
    NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
    UNICODE_STRING         DeviceName;
    UNICODE_STRING         DeviceLinkUnicodeString;
    PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION+1];
    NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
    PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
    PDRIVER_OBJECT                  DriverObject;
   
    DEBUGP(DL_TRACE, "==>FilterRegisterDevice\n");

    NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION+1) * sizeof(PDRIVER_DISPATCH));

    DispatchTable[IRP_MJ_CREATE] = FilterDispatch;
    DispatchTable[IRP_MJ_CLEANUP] = FilterDispatch;
    DispatchTable[IRP_MJ_CLOSE] = FilterDispatch;
    DispatchTable[IRP_MJ_DEVICE_CONTROL] = FilterDeviceIoControl;


    NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
    NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);

    //
    // Create a device object and register our dispatch handlers
    //
    NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

    DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

    DeviceAttribute.DeviceName = &DeviceName;
    DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
    DeviceAttribute.MajorFunctions = &DispatchTable[0];
    DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);
	UNICODE_STRING sddlString;
	RtlInitUnicodeString(&sddlString,L"D:p(A;;GA;;;SY)");
	DeviceAttribute.DefaultSDDLString = &sddlString;

    Status = NdisRegisterDeviceEx(
                FilterDriverHandle,
                &DeviceAttribute,
                &DeviceObject,
                &NdisFilterDeviceHandle
                );


    if (Status == NDIS_STATUS_SUCCESS)
    {
		*Extension = FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);

        FilterDeviceExtension->Signature = 'FTDR';
        FilterDeviceExtension->Handle = FilterDriverHandle;
		KeInitializeSpinLock(&FilterDeviceExtension->QLock);
		PRULES_LISTS FilterRules = ExAllocatePool(PagedPool, sizeof(RULES_LISTS));
		FilterRules->IsActive = FALSE;
		FilterRules->FirstRuleIPv4 = NULL;
		FilterDeviceExtension->FilterRules = FilterRules;

		//Read rule file and set the rule.
		LoadRule(FilterDeviceExtension);

        //
        // Workaround NDIS bug
        //
        DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
    }


    DEBUGP(DL_TRACE, "<==FilterRegisterDevice: %x\n", Status);

    return (Status);

}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FilterDeregisterDevice(
    VOID
    )

{
    if (NdisFilterDeviceHandle != NULL)
    {
        NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
    }

    NdisFilterDeviceHandle = NULL;

}

_Use_decl_annotations_
NTSTATUS
FilterDispatch(
    PDEVICE_OBJECT       DeviceObject,
    PIRP                 Irp
    )
{
    PIO_STACK_LOCATION       IrpStack;
    NTSTATUS                 Status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpStack->MajorFunction)
    {
        case IRP_MJ_CREATE:
            break;

        case IRP_MJ_CLEANUP:
            break;

        case IRP_MJ_CLOSE:
            break;

        default:
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

_Use_decl_annotations_
NTSTATUS
FilterDeviceIoControl(
    PDEVICE_OBJECT        DeviceObject,
    PIRP                  Irp
    )
{
    PIO_STACK_LOCATION          IrpSp;
    NTSTATUS                    Status = STATUS_SUCCESS;
    PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;
    PUCHAR                      InputBuffer;
    PUCHAR                      OutputBuffer;
    ULONG                       InputBufferLength, OutputBufferLength;
    PLIST_ENTRY                 Link;
    PUCHAR                      pInfo;
    ULONG                       InfoLength = 0;
    PMS_FILTER                  pFilter = NULL;
    BOOLEAN                     bFalse = FALSE;


    UNREFERENCED_PARAMETER(DeviceObject);

	KIRQL OldIrql;

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->FileObject == NULL)
    {
        return(STATUS_UNSUCCESSFUL);
    }


    FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);

    ASSERT(FilterDeviceExtension->Signature == 'FTDR');

    Irp->IoStatus.Information = 0;

	KeAcquireSpinLock(&FilterDeviceExtension->QLock, &OldIrql);
    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
		case IOCTL_ADD_IPV4_RULE:
			DbgPrint("IOCTL_ADD_IPV4_RULE BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != sizeof(RULE_IPV4))
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			PRULE_IPV4 pRuleIPv4 = ExAllocatePool(NonPagedPool, sizeof(RULE_IPV4));
			RtlCopyMemory(pRuleIPv4, InputBuffer, InputBufferLength);
			AddIPv4Rule(FilterDeviceExtension, pRuleIPv4);
			DbgPrint("IOCTL_ADD_IPV4_RULE END\n");
			break;
		case IOCTL_DEL_IPV4_RULE:
			DbgPrint("IOCTL_DEL_IPV4_RULE BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != sizeof(ULONG))
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			ULONG IdIPv4 = *((PULONG)(InputBuffer));
			DelIPv4Rule(FilterDeviceExtension, IdIPv4);
			DbgPrint("IOCTL_DEL_IPV4_RULE END\n");
			break;
			case IOCTL_ACTIVATE_FILTER:
			DbgPrint("IOCTL_ACTIVATE_FILTER BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != 0)
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			ActivateRules(FilterDeviceExtension);
			DbgPrint("IOCTL_ACTIVATE_FILTER END\n");
			break;
		case IOCTL_DEACTIVATE_FILTER:
			DbgPrint("IOCTL_DEACTIVATE_FILTER BEGIN\n");
			InputBuffer = Irp->UserBuffer;
			InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			if (InputBufferLength != 0)
			{
				Status = NDIS_STATUS_FAILURE;
				break;
			}
			DeactivateRules(FilterDeviceExtension);
			DbgPrint("IOCTL_DEACTIVATE_FILTER END\n");
			break;
        case IOCTL_FILTER_RESTART_ALL:
            break;

        case IOCTL_FILTER_RESTART_ONE_INSTANCE:
            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

            pFilter = filterFindFilterModule (InputBuffer, InputBufferLength);

            if (pFilter == NULL)
            {

                break;
            }

            NdisFRestartFilter(pFilter->FilterHandle);

            break;

        case IOCTL_FILTER_ENUERATE_ALL_INSTANCES:

            InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
            InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;


            pInfo = OutputBuffer;

            FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

            Link = FilterModuleList.Flink;

            while (Link != &FilterModuleList)
            {
                pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);


                InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));

                if (InfoLength <= OutputBufferLength)
                {
                    *(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
                    NdisMoveMemory(pInfo + sizeof(USHORT),
                                   (PUCHAR)(pFilter->FilterModuleName.Buffer),
                                   pFilter->FilterModuleName.Length);

                    pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
                }

                Link = Link->Flink;
            }

            FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
            if (InfoLength <= OutputBufferLength)
            {

                Status = NDIS_STATUS_SUCCESS;
            }
            //
            // Buffer is small
            //
            else
            {
                Status = STATUS_BUFFER_TOO_SMALL;
            }
            break;


        default:
            break;
    }
	KeReleaseSpinLock(&FilterDeviceExtension->QLock, OldIrql);
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = InfoLength;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;


}


_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
    _In_reads_bytes_(BufferLength)
         PUCHAR                   Buffer,
    _In_ ULONG                    BufferLength
    )
{

   PMS_FILTER              pFilter;
   PLIST_ENTRY             Link;
   BOOLEAN                  bFalse = FALSE;

   FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

   Link = FilterModuleList.Flink;

   while (Link != &FilterModuleList)
   {
       pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

       if (BufferLength >= pFilter->FilterModuleName.Length)
       {
           if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
           {
               FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
               return pFilter;
           }
       }

       Link = Link->Flink;
   }

   FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
   return NULL;
}

void  LoadRule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension)
{
	UNICODE_STRING     uniName;
	OBJECT_ATTRIBUTES  objAttr;

	RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\WINDOWS\\Rules.dat");  // or L"\\SystemRoot\\example.txt"
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE   handle;
	NTSTATUS ntstatus;
	IO_STATUS_BLOCK    ioStatusBlock;

	// Do not try to perform any file operations at higher IRQL levels.
	// Instead, you may use a work item or a system worker thread to perform file operations.

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		DbgPrint("[LoadRule]KeGetCurrentIrql error");
		return;
	}

	//Open rule file.
	DEBUGP(DL_TRACE, "===>Open the rule file...\n");
	ntstatus = ZwCreateFile(&handle,
		GENERIC_READ,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (!NT_SUCCESS(ntstatus))
	{
		DbgPrint("[LoadRule]Can't open the rule file,error code:[%d]", ntstatus);
		return;
	}

	LARGE_INTEGER      byteOffset;
	byteOffset.LowPart = byteOffset.HighPart = 0;
	ULONG ruleCnt = 0;

	ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
		&ruleCnt, 4, &byteOffset, NULL);
	if (!NT_SUCCESS(ntstatus))
	{
		ZwClose(handle);
		DbgPrint("[LoadRule]Can't read the rule file,error code:[%d]", ntstatus);
		return;
	}

	ULONG i;
	for (i = 0; i < ruleCnt; i++)
	{
		PRULE_IPV4 pRuleIPv4 = ExAllocatePool(NonPagedPool, sizeof(RULE_IPV4));
		ntstatus = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
			pRuleIPv4, sizeof(RULE_IPV4), &byteOffset, NULL);
		if (!NT_SUCCESS(ntstatus))
			break;
		AddIPv4Rule(FilterDeviceExtension, pRuleIPv4);
	}
	ActivateRules(FilterDeviceExtension);

	ZwClose(handle);
	DbgPrint("[LoadRule]Load Status", ntstatus);
}


VOID AddIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN PRULE_IPV4 Rule)
{
	DbgPrint("AddIPv4Rule\n");
	DbgPrint("Id: %lu Protocol:%d IP:%d.%d.%d.%d Port:%d\n",
		Rule->Id,
		Rule->Protocol,
		Rule->IP[0],
		Rule->IP[1],
		Rule->IP[2],
		Rule->IP[3],
		Rule->Port);
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	PRULE_IPV4 List = RulesLists->FirstRuleIPv4;
	Rule->Next = List;
	RulesLists->FirstRuleIPv4 = Rule;
}

VOID DelIPv4Rule(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension, IN ULONG Id)
{
	DbgPrint("DelIPv4Rule\n");
	DbgPrint("Id: %lu\n",Id);
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	PRULE_IPV4 CurrentRule = RulesLists->FirstRuleIPv4;

	while (CurrentRule != NULL && CurrentRule->Id == Id)
	{
		RulesLists->FirstRuleIPv4 = CurrentRule->Next;
		ExFreePool(CurrentRule);
		CurrentRule = RulesLists->FirstRuleIPv4;
	}

	if (CurrentRule == NULL)
	{
		return;
	}

	PRULE_IPV4 PreviousRule = CurrentRule;
	CurrentRule = CurrentRule->Next;

	while (CurrentRule != NULL)
	{
		if (CurrentRule->Id == Id)
		{
			PreviousRule->Next = CurrentRule->Next;
			ExFreePool(CurrentRule);
		}
		PreviousRule = CurrentRule;
		CurrentRule = CurrentRule->Next;
	}
}

VOID ActivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension)
{
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	RulesLists->IsActive = TRUE;
}

VOID DeactivateRules(IN PFILTER_DEVICE_EXTENSION FilterDeviceExtension)
{
	PRULES_LISTS RulesLists = FilterDeviceExtension->FilterRules;
	RulesLists->IsActive = FALSE;
}



