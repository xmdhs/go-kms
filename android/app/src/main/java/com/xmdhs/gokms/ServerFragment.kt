package com.xmdhs.gokms

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.color.MaterialColors
import com.xmdhs.gokms.databinding.FragmentServerBinding
import com.xmdhs.gokms.databinding.ItemAddressBinding
import kotlinx.coroutines.launch

class ServerFragment : Fragment() {
    private var _binding: FragmentServerBinding? = null
    private val binding get() = _binding!!

    private lateinit var settings: SettingsStore
    private var notificationGranted = false
    private var running = false
    private var address = ""
    private var lastRefreshedPort: String? = null

    private val notificationLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        notificationGranted = granted
        if (granted) {
            LogBuffer.appendServer(getString(R.string.notification_granted))
        } else {
            LogBuffer.appendServer(getString(R.string.notification_denied))
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        _binding = FragmentServerBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        settings = SettingsStore(requireContext().applicationContext)
        notificationGranted = isNotificationGranted(requireContext())

        val args = settings.loadServer()
        binding.ipInput.setText(args.ip)
        binding.portInput.setText(args.port)
        binding.epidInput.setText(args.epid)
        binding.countInput.setText(args.count)
        binding.hwidInput.setText(args.hwid)

        binding.ipInput.doAfterTextChanged { onArgsChanged() }
        binding.portInput.doAfterTextChanged { onArgsChanged() }
        binding.epidInput.doAfterTextChanged { onArgsChanged() }
        binding.countInput.doAfterTextChanged { onArgsChanged() }
        binding.hwidInput.doAfterTextChanged { onArgsChanged() }

        binding.hwidRandomButton.setOnClickListener {
            binding.hwidInput.setText("RANDOM")
        }
        binding.hwidDefaultButton.setOnClickListener {
            binding.hwidInput.setText("364F463A8863D35F")
        }

        binding.refreshAddressesButton.setOnClickListener { refreshListenAddresses() }
        binding.startButton.setOnClickListener { startServer() }
        binding.stopButton.setOnClickListener { stopServer() }
        binding.logPanel.onClear = { LogBuffer.clearServer() }

        refreshListenAddresses()
        renderServiceState()

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    LogBuffer.serverLines.collect { binding.logPanel.submitLogs(it) }
                }
                launch {
                    GoKmsServiceState.running.collect {
                        running = it
                        renderServiceState()
                    }
                }
                launch {
                    GoKmsServiceState.address.collect {
                        address = it
                        renderServiceState()
                    }
                }
            }
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }

    private fun serverArgs(): ServerArgs {
        return ServerArgs(
            ip = binding.ipInput.text?.toString().orEmpty(),
            port = binding.portInput.text?.toString().orEmpty(),
            epid = binding.epidInput.text?.toString().orEmpty(),
            count = binding.countInput.text?.toString().orEmpty(),
            hwid = binding.hwidInput.text?.toString().orEmpty(),
        )
    }

    private fun onArgsChanged() {
        val args = serverArgs()
        settings.saveServer(args)
        binding.bindAddressText.text = getString(R.string.bind_address, args.displayAddress())

        val port = args.port.trim().ifBlank { "1688" }
        if (port != lastRefreshedPort) refreshListenAddresses()
    }

    private fun refreshListenAddresses() {
        val args = serverArgs()
        binding.bindAddressText.text = getString(R.string.bind_address, args.displayAddress())

        val port = args.port.trim().ifBlank { "1688" }
        lastRefreshedPort = port
        val addresses = DeviceAddressProvider.listenAddresses(port)
        binding.addressesContainer.removeAllViews()
        binding.addressesPlaceholderText.isVisible = addresses.isEmpty()
        binding.addressesLabelText.isVisible = addresses.isNotEmpty()
        binding.addressesContainer.isVisible = addresses.isNotEmpty()

        val inflater = LayoutInflater.from(requireContext())
        addresses.forEach { deviceAddress ->
            val addressView = ItemAddressBinding.inflate(inflater, binding.addressesContainer, false)
            addressView.root.text = deviceAddress
            binding.addressesContainer.addView(addressView.root)
        }
    }

    private fun renderServiceState() {
        binding.statusText.text = if (running) {
            getString(R.string.server_status_running, address)
        } else {
            getString(R.string.server_status_stopped)
        }

        val primary = MaterialColors.getColor(
            binding.headerIcon,
            com.google.android.material.R.attr.colorPrimary,
            0,
        )
        val variant = MaterialColors.getColor(
            binding.headerIcon,
            com.google.android.material.R.attr.colorOnSurfaceVariant,
            0,
        )
        binding.headerIcon.imageTintList = ColorStateList.valueOf(if (running) primary else variant)
        binding.statusText.setTextColor(if (running) primary else variant)
        binding.startButton.isEnabled = !running
        binding.stopButton.isEnabled = running
    }

    private fun startServer() {
        val args = serverArgs()
        args.validate()?.let {
            LogBuffer.appendServer(getString(R.string.invalid_args, it))
            return
        }
        settings.saveServer(args)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notificationGranted) {
            notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            LogBuffer.appendServer(getString(R.string.notification_required))
            return
        }

        val displayAddresses = DeviceAddressProvider.listenAddresses(args.port)
        if (displayAddresses.isNotEmpty()) {
            LogBuffer.appendServer(
                getString(R.string.device_addresses_log, displayAddresses.joinToString(", ")),
            )
        }

        ContextCompat.startForegroundService(
            requireContext(),
            GoKmsForegroundService.startIntent(requireContext(), args),
        )
    }

    private fun stopServer() {
        requireContext().startService(GoKmsForegroundService.stopIntent(requireContext()))
    }

    private fun isNotificationGranted(context: Context): Boolean {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
    }
}
