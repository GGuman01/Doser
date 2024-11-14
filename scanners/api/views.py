import os

from django.http import FileResponse
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from ..utils import get_domain_name
from .serializers import DomainSerializer
from ..scanner_scripts.nuclei import run_nuclei_scan
from ..scanner_scripts.ddoser import run_scans as run_zap_scan
from ..scanner_scripts.hostcavery import exceute_whois_dns_scans


class HostCaveryAPIView(generics.GenericAPIView):

    serializer_class = DomainSerializer
    permission_classes = [AllowAny]

    def post(self, *args, **kwargs):

        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        domain = get_domain_name(serializer.data["url"])
        file_path = "whois_dns_results.txt"
        exceute_whois_dns_scans(domain=domain, output_file=file_path)

        if os.path.exists(file_path):
            response = FileResponse(open(file_path, "rb"))
            response["Content-Disposition"] = (
                f'attachment; filename="{os.path.basename(file_path)}"'
            )
            return response

        return Response({"message": "Could not send reponse text"})


class DDoserAPIView(generics.GenericAPIView):

    serializer_class = DomainSerializer
    permission_classes = [AllowAny]

    def post(self, *args, **kwargs):

        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        target_url = get_domain_name(serializer.data["url"])
        file_path = "zap_scnr/output.txt"

        run_zap_scan(target_url)

        if os.path.exists(file_path):
            response = FileResponse(open(file_path, "rb"))
            response["Content-Disposition"] = (
                f'attachment; filename="{os.path.basename(file_path)}"'
            )
            return response

        return Response({"message": "An error occured"})


class NucleiScanAPIView(generics.GenericAPIView):

    serializer_class = DomainSerializer
    permission_classes = [AllowAny]

    def post(self, *args, **kwargs):

        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        target_url = get_domain_name(serializer.data["url"])
        file_path = "nuclei_results/nuclei_result.txt"

        run_nuclei_scan(
            target_uri=target_url,
            report_path="nuclei_results/nuclei_report_0.txt",
        )

        if os.path.exists(file_path):
            response = FileResponse(open(file_path, "rb"))
            response["Content-Disposition"] = (
                f'attachment; filename="{os.path.basename(file_path)}"'
            )
            return response

        return Response({"message": "An error occured"})
