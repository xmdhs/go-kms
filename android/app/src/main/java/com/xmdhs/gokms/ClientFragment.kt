package com.xmdhs.gokms

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.xmdhs.gokms.databinding.FragmentClientBinding
import kotlinx.coroutines.launch

class ClientFragment : Fragment() {
    private var _binding: FragmentClientBinding? = null
    private val binding get() = _binding!!

    private lateinit var settings: SettingsStore

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?,
    ): View {
        _binding = FragmentClientBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        settings = SettingsStore(requireContext().applicationContext)

        val args = settings.loadClient()
        binding.modeInput.setSimpleItems(ProductModes.toTypedArray())
        binding.ipInput.setText(args.ip)
        binding.portInput.setText(args.port)
        binding.modeInput.setText(args.mode, false)
        binding.cmidInput.setText(args.cmid)
        binding.nameInput.setText(args.name)

        binding.modeInput.setOnItemClickListener { _, _, _, _ -> onArgsChanged() }

        binding.ipInput.doAfterTextChanged { onArgsChanged() }
        binding.portInput.doAfterTextChanged { onArgsChanged() }
        binding.cmidInput.doAfterTextChanged { onArgsChanged() }
        binding.nameInput.doAfterTextChanged { onArgsChanged() }

        binding.runButton.setOnClickListener { runClient() }
        binding.logPanel.onClear = { LogBuffer.clearClient() }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    LogBuffer.clientLines.collect { binding.logPanel.submitLogs(it) }
                }
                launch {
                    ClientRunner.running.collect { renderRunningState(it) }
                }
            }
        }
    }

    override fun onDestroyView() {
        _binding = null
        super.onDestroyView()
    }

    private fun clientArgs(): ClientArgs {
        return ClientArgs(
            ip = binding.ipInput.text?.toString().orEmpty(),
            port = binding.portInput.text?.toString().orEmpty(),
            mode = binding.modeInput.text?.toString().orEmpty(),
            cmid = binding.cmidInput.text?.toString().orEmpty(),
            name = binding.nameInput.text?.toString().orEmpty(),
        )
    }

    private fun onArgsChanged() {
        settings.saveClient(clientArgs())
    }

    private fun renderRunningState(running: Boolean) {
        binding.runButton.isEnabled = !running
        binding.runButton.setText(if (running) R.string.client_running else R.string.run_client)
    }

    private fun runClient() {
        val args = clientArgs()
        args.validate()?.let {
            LogBuffer.appendClient(getString(R.string.invalid_args, it))
            return
        }
        settings.saveClient(args)
        ClientRunner.run(args)
    }
}
