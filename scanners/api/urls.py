from django.urls import path

from . import views


urlpatterns = [
    path("hostcavery/", views.HostCaveryAPIView.as_view(), name="hostcavery"),
    path("ddoser/", views.DDoserAPIView.as_view(), name="ddoser"),
    path("nuclei/", views.NucleiScanAPIView.as_view(), name="nuclei"),
]
