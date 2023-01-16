node ('sdle_automation'){

  stage('Generate BDBA scan report'){
    sh "cp /home/fdo/tpm_ecdsa256_ccm_bin.tar.gz /home/fdo/protecode.py $WORKSPACE"
    sh "python3 protecode.py --application_file_name tpm_ecdsa256_ccm_bin.tar.gz --password ${sys_mpci_password}"
  }
  
  stage('Upload BDBA evidence to SDLE'){
    sh "sudo docker run -v $WORKSPACE:/sdle amr-registry.caas.intel.com/owr/abi_lnx:latest abi sdle upload --report_path /sdle/test_bdba_scan_report.pdf --task_id CT7 --submitter_idsid ${submitter_idsid}  --api_token ${api_token} --server_url ${server_url} --sdl_project_id ${sdl_project_id} --debug"
  }

}